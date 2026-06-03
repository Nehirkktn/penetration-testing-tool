"""ScanResult veri modeli için detaylı testler."""

import json
from datetime import datetime, timedelta
import pytest

from siber_savascilar.core.models import (
    ScanResult, Vulnerability, Severity, ScanStatus, VulnType
)


class TestScanResultBasic:
    """Temel oluşturma ve alanlar."""

    def test_empty_creation(self):
        r = ScanResult()
        assert r.vulnerabilities == []
        assert r.open_ports == []
        assert r.modules_run == []

    def test_with_target(self):
        r = ScanResult(target_url="http://test.com")
        assert r.target_url == "http://test.com"

    def test_default_status_is_pending(self):
        r = ScanResult()
        assert r.status == ScanStatus.PENDING

    def test_is_vulnerable_false_when_empty(self):
        r = ScanResult()
        assert r.is_vulnerable is False

    def test_is_vulnerable_true_when_has_vulns(self):
        r = ScanResult()
        r.add_vulnerability(Vulnerability(severity=Severity.LOW))
        assert r.is_vulnerable is True

    def test_vulnerability_count_zero(self):
        assert ScanResult().vulnerability_count == 0

    def test_vulnerability_count_after_adds(self):
        r = ScanResult()
        for _ in range(5):
            r.add_vulnerability(Vulnerability())
        assert r.vulnerability_count == 5


class TestScanResultDuration:
    """duration_seconds property."""

    def test_duration_none_when_not_started(self):
        r = ScanResult()
        assert r.duration_seconds is None

    def test_duration_none_when_only_started(self):
        r = ScanResult(started_at=datetime.now())
        assert r.duration_seconds is None

    def test_duration_calculated_correctly(self):
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 10, 0, 45)
        r = ScanResult(started_at=start, finished_at=end)
        assert r.duration_seconds == 45.0

    def test_duration_supports_fractional_seconds(self):
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = start + timedelta(seconds=1.5)
        r = ScanResult(started_at=start, finished_at=end)
        assert r.duration_seconds == 1.5

    def test_duration_for_long_scan(self):
        start = datetime(2025, 1, 1, 10, 0, 0)
        end = datetime(2025, 1, 1, 10, 15, 0)
        r = ScanResult(started_at=start, finished_at=end)
        assert r.duration_seconds == 900.0


class TestScanResultSeverityBreakdown:
    """severity_breakdown property."""

    def test_breakdown_empty(self):
        r = ScanResult()
        brk = r.severity_breakdown
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            assert brk[sev] == 0

    def test_breakdown_one_critical(self):
        r = ScanResult()
        r.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
        assert r.severity_breakdown["Critical"] == 1
        assert r.severity_breakdown["High"] == 0

    def test_breakdown_mixed(self):
        r = ScanResult()
        for s in [Severity.CRITICAL, Severity.CRITICAL, Severity.HIGH,
                  Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM,
                  Severity.LOW]:
            r.add_vulnerability(Vulnerability(severity=s))
        brk = r.severity_breakdown
        assert brk["Critical"] == 2
        assert brk["High"] == 1
        assert brk["Medium"] == 3
        assert brk["Low"] == 1

    def test_breakdown_includes_all_severities(self):
        r = ScanResult()
        brk = r.severity_breakdown
        # Tüm severity'ler key olarak var olmalı
        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            assert sev in brk

    def test_breakdown_ignores_invalid_severity(self):
        r = ScanResult()
        r.add_vulnerability(Vulnerability(severity="Bilinmeyen"))
        # Tüm sayaçlar 0 olmalı
        brk = r.severity_breakdown
        assert sum(brk.values()) == 0


class TestScanResultHighestSeverity:
    """highest_severity property."""

    def test_highest_none_when_empty(self):
        r = ScanResult()
        assert r.highest_severity is None

    def test_highest_critical(self):
        r = ScanResult()
        r.add_vulnerability(Vulnerability(severity=Severity.LOW))
        r.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
        r.add_vulnerability(Vulnerability(severity=Severity.MEDIUM))
        assert r.highest_severity == Severity.CRITICAL

    def test_highest_high_no_critical(self):
        r = ScanResult()
        r.add_vulnerability(Vulnerability(severity=Severity.LOW))
        r.add_vulnerability(Vulnerability(severity=Severity.HIGH))
        r.add_vulnerability(Vulnerability(severity=Severity.MEDIUM))
        assert r.highest_severity == Severity.HIGH

    def test_highest_with_single_vuln(self):
        r = ScanResult()
        r.add_vulnerability(Vulnerability(severity=Severity.MEDIUM))
        assert r.highest_severity == Severity.MEDIUM


class TestScanResultAddVulnerabilities:
    """add_vulnerability ve add_vulnerabilities."""

    def test_add_single(self):
        r = ScanResult()
        r.add_vulnerability(Vulnerability())
        assert len(r.vulnerabilities) == 1

    def test_add_multiple_individually(self):
        r = ScanResult()
        for _ in range(3):
            r.add_vulnerability(Vulnerability())
        assert len(r.vulnerabilities) == 3

    def test_add_list(self):
        r = ScanResult()
        vulns = [Vulnerability() for _ in range(5)]
        r.add_vulnerabilities(vulns)
        assert len(r.vulnerabilities) == 5

    def test_add_empty_list(self):
        r = ScanResult()
        r.add_vulnerabilities([])
        assert len(r.vulnerabilities) == 0

    def test_add_preserves_order(self):
        r = ScanResult()
        v1 = Vulnerability(target="first")
        v2 = Vulnerability(target="second")
        r.add_vulnerability(v1)
        r.add_vulnerability(v2)
        assert r.vulnerabilities[0].target == "first"
        assert r.vulnerabilities[1].target == "second"


class TestScanResultSummary:
    """generate_summary metodu."""

    def test_summary_no_vulns(self):
        r = ScanResult(target_url="http://t.com", status=ScanStatus.COMPLETED)
        summary = r.generate_summary()
        assert "zafiyet tespit edilmedi" in summary.lower()
        assert "http://t.com" in summary

    def test_summary_with_vulns(self):
        r = ScanResult(target_url="http://t.com")
        r.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
        r.add_vulnerability(Vulnerability(severity=Severity.HIGH))
        summary = r.generate_summary()
        assert "2 adet zafiyet" in summary

    def test_summary_error_status(self):
        r = ScanResult(status=ScanStatus.ERROR, error_message="Bağlantı yok")
        summary = r.generate_summary()
        assert "hata" in summary.lower()
        assert "Bağlantı yok" in summary

    def test_summary_timeout_status(self):
        r = ScanResult(status=ScanStatus.TIMEOUT)
        summary = r.generate_summary()
        assert "zaman aşımı" in summary.lower()

    def test_summary_includes_severity_counts(self):
        r = ScanResult(target_url="http://t.com")
        r.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
        r.add_vulnerability(Vulnerability(severity=Severity.MEDIUM))
        summary = r.generate_summary()
        assert "Kritik" in summary
        assert "Orta" in summary

    def test_summary_persists_to_field(self):
        r = ScanResult(target_url="http://t.com")
        r.add_vulnerability(Vulnerability(severity=Severity.HIGH))
        result = r.generate_summary()
        # generate_summary hem return ediyor hem field'a yazıyor
        assert r.summary == result
        assert len(r.summary) > 0


class TestScanResultJSON:
    """to_json ve to_dict."""

    def test_to_json_returns_string(self):
        r = ScanResult(target_url="http://t.com")
        result = r.to_json()
        assert isinstance(result, str)

    def test_to_json_is_valid_json(self):
        r = ScanResult(target_url="http://t.com")
        data = json.loads(r.to_json())
        assert data["target_url"] == "http://t.com"

    def test_to_dict_has_computed_fields(self):
        r = ScanResult(target_url="http://t.com")
        r.add_vulnerability(Vulnerability(severity=Severity.HIGH))
        d = r.to_dict()
        assert d["vulnerability_count"] == 1
        assert d["highest_severity"] == Severity.HIGH
        assert d["is_vulnerable"] is True

    def test_to_dict_includes_vulnerabilities(self):
        r = ScanResult()
        r.add_vulnerability(Vulnerability(vuln_type=VulnType.SQLI))
        d = r.to_dict()
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["vuln_type"] == VulnType.SQLI

    def test_to_dict_handles_none_dates(self):
        """started_at None ise to_dict yine de çalışmalı."""
        r = ScanResult(target_url="http://t.com")
        d = r.to_dict()
        assert d["started_at"] is None

    def test_json_with_turkish_characters(self):
        """Türkçe karakterler düzgün serialize olmalı."""
        r = ScanResult(target_url="http://türkçe.com")
        r.add_vulnerability(Vulnerability(description="Açıklama içeriği"))
        data = json.loads(r.to_json())
        assert data["target_url"] == "http://türkçe.com"
        assert "Açıklama" in data["vulnerabilities"][0]["description"]


class TestScanResultString:
    """__str__ metodu."""

    def test_str_contains_target(self):
        r = ScanResult(target_url="http://test.com")
        assert "http://test.com" in str(r)

    def test_str_contains_status(self):
        r = ScanResult(target_url="x", status=ScanStatus.COMPLETED)
        assert "completed" in str(r)

    def test_str_contains_vuln_count(self):
        r = ScanResult(target_url="x")
        r.add_vulnerability(Vulnerability())
        r.add_vulnerability(Vulnerability())
        assert "2" in str(r)
