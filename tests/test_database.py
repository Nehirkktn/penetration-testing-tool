"""Veritabanı testleri — tempfile ile izole çalışır."""

import os
import tempfile
from datetime import datetime

import pytest

from siber_savascilar.core.database import Database
from siber_savascilar.core.models import (
    ScanResult, Vulnerability, Severity, ScanStatus, VulnType
)


@pytest.fixture
def db():
    """Geçici DB ile izole test ortamı."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        yield Database(db_path)
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_database_initialization(db):
    """Şema oluşturuldu mu?"""
    with db.connection() as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = [t["name"] for t in tables]
        assert "users" in names
        assert "scan_configs" in names
        assert "scans" in names
        assert "vulnerabilities" in names
        assert "reports" in names


def test_create_scan(db):
    scan_id = db.create_scan("http://test.com", ["sqli", "xss"])
    assert scan_id > 0

    scan = db.get_scan(scan_id)
    assert scan["target_url"] == "http://test.com"
    assert scan["status"] == ScanStatus.RUNNING


def test_finish_scan(db):
    scan_id = db.create_scan("http://test.com", ["sqli"])

    result = ScanResult(
        scan_id=scan_id,
        target_url="http://test.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(),
        finished_at=datetime.now(),
        modules_run=["sqli"],
        open_ports=[80, 443],
    )
    result.add_vulnerability(Vulnerability(
        vuln_type=VulnType.SQLI,
        severity=Severity.CRITICAL,
        target="http://test.com",
        description="Test açık",
        payload="' OR 1=1--",
    ))

    db.finish_scan(result)

    # Doğrula
    scan = db.get_scan(scan_id)
    assert scan["status"] == ScanStatus.COMPLETED

    vulns = db.get_vulnerabilities(scan_id)
    assert len(vulns) == 1
    assert vulns[0]["vuln_type"] == VulnType.SQLI
    assert vulns[0]["severity"] == Severity.CRITICAL

    report = db.get_report(scan_id)
    assert report is not None
    assert "Test açık" in report["summary"] or scan["target_url"] in report["summary"]


def test_list_scans(db):
    db.create_scan("http://test1.com", ["sqli"])
    db.create_scan("http://test2.com", ["xss"])
    db.create_scan("http://test3.com", ["misconfig"])

    scans = db.list_scans()
    assert len(scans) == 3
    # En yeni önce
    assert scans[0]["target_url"] == "http://test3.com"


def test_get_stats(db):
    # Boşken
    stats = db.get_stats()
    assert stats["total_scans"] == 0
    assert stats["total_vulnerabilities"] == 0

    # Bir tarama + zafiyetler
    scan_id = db.create_scan("http://test.com", ["sqli"])
    result = ScanResult(
        scan_id=scan_id, target_url="http://test.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(), finished_at=datetime.now(),
    )
    result.add_vulnerability(Vulnerability(severity=Severity.CRITICAL, target="x"))
    result.add_vulnerability(Vulnerability(severity=Severity.HIGH, target="x"))
    result.add_vulnerability(Vulnerability(severity=Severity.LOW, target="x"))
    db.finish_scan(result)

    stats = db.get_stats()
    assert stats["total_scans"] == 1
    assert stats["total_vulnerabilities"] == 3
    assert stats["critical_count"] == 1
    assert stats["high_count"] == 1


def test_delete_scan(db):
    scan_id = db.create_scan("http://test.com", ["sqli"])
    result = ScanResult(
        scan_id=scan_id, target_url="http://test.com",
        status=ScanStatus.COMPLETED,
        started_at=datetime.now(), finished_at=datetime.now(),
    )
    result.add_vulnerability(Vulnerability(severity=Severity.HIGH, target="x"))
    db.finish_scan(result)

    assert db.get_scan(scan_id) is not None
    assert len(db.get_vulnerabilities(scan_id)) == 1

    db.delete_scan(scan_id)

    assert db.get_scan(scan_id) is None
    # CASCADE ile zafiyetler de silinmiş olmalı
    assert len(db.get_vulnerabilities(scan_id)) == 0
