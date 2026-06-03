"""Veri modeli testleri."""

import json
from datetime import datetime
from siber_savascilar.core.models import (
    Vulnerability, ScanResult, Severity, ScanStatus, VulnType
)


def test_severity_compare():
    assert Severity.compare(Severity.CRITICAL, Severity.LOW) > 0
    assert Severity.compare(Severity.LOW, Severity.CRITICAL) < 0
    assert Severity.compare(Severity.HIGH, Severity.HIGH) == 0


def test_severity_validation():
    assert Severity.is_valid("Critical")
    assert Severity.is_valid("Low")
    assert not Severity.is_valid("Çok-Kritik")
    assert not Severity.is_valid("")


def test_severity_color():
    assert Severity.color(Severity.CRITICAL).startswith("#")
    assert Severity.color("Unknown").startswith("#")  # Default value


def test_vulnerability_creation():
    v = Vulnerability(
        vuln_type=VulnType.SQLI,
        severity=Severity.CRITICAL,
        target="http://test.com",
        description="Test açık",
    )
    assert v.vuln_type == VulnType.SQLI
    assert v.severity == Severity.CRITICAL
    assert v.discovered_at is not None  # __post_init__ ile atanmalı


def test_vulnerability_to_db_record():
    v = Vulnerability(
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        target="http://test.com",
        payload="<script>alert(1)</script>",
        details={"context": "html"},
    )
    rec = v.to_db_record()
    assert rec["vuln_type"] == VulnType.XSS
    assert rec["payload"] == "<script>alert(1)</script>"
    # details_json valid JSON olmalı
    assert json.loads(rec["details_json"]) == {"context": "html"}


def test_scan_result_severity_breakdown():
    result = ScanResult(target_url="http://test.com")
    result.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
    result.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
    result.add_vulnerability(Vulnerability(severity=Severity.HIGH))
    result.add_vulnerability(Vulnerability(severity=Severity.LOW))

    brk = result.severity_breakdown
    assert brk["Critical"] == 2
    assert brk["High"] == 1
    assert brk["Low"] == 1
    assert brk["Medium"] == 0


def test_scan_result_highest_severity():
    result = ScanResult(target_url="http://test.com")
    assert result.highest_severity is None  # Boşken None

    result.add_vulnerability(Vulnerability(severity=Severity.LOW))
    result.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
    result.add_vulnerability(Vulnerability(severity=Severity.MEDIUM))
    assert result.highest_severity == Severity.CRITICAL


def test_scan_result_duration():
    result = ScanResult(target_url="http://test.com")
    result.started_at = datetime(2025, 1, 1, 10, 0, 0)
    result.finished_at = datetime(2025, 1, 1, 10, 0, 30)
    assert result.duration_seconds == 30


def test_scan_result_json_serialization():
    result = ScanResult(
        target_url="http://test.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(),
    )
    result.add_vulnerability(Vulnerability(
        vuln_type=VulnType.SQLI,
        severity=Severity.HIGH,
        target="http://test.com",
    ))

    json_str = result.to_json()
    data = json.loads(json_str)
    assert data["target_url"] == "http://test.com"
    assert data["vulnerability_count"] == 1
    assert len(data["vulnerabilities"]) == 1


def test_scan_result_summary_generation():
    result = ScanResult(target_url="http://test.com")
    result.status = ScanStatus.COMPLETED
    # Boş sonuç için temiz mesaj
    summary = result.generate_summary()
    assert "zafiyet tespit edilmedi" in summary.lower()

    # Zafiyetli sonuç
    result.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
    summary = result.generate_summary()
    assert "1 adet zafiyet" in summary
