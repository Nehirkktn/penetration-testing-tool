"""
SQLMap Scanner — Birim Testleri
=================================

SQLMapScanner sinifinin unit testleri.
SQLMap'in sistemde kurulu olup olmamasindan bagimsiz olarak calisir.
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.scanners.sqlmap_scanner import (
    SQLMapScanner,
    SQLMapNotFoundError,
    SQLMapScanError,
)
from src.config.sqlmap_config import SQLMapConfig
from src.models.scan_result import ScanResult, ScanStatus, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Mock SQLMap ciktilari
# ─────────────────────────────────────────────────────────────────────────────

MOCK_VULNERABLE_STDOUT = """
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 14:30:00 /2026-04-05/

sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5765=5765

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-7181 UNION ALL SELECT NULL,CONCAT(0x716a787071),NULL-- -
---
back-end DBMS: MySQL >= 5.0
"""

MOCK_NO_VULN_STDOUT = """
[*] starting @ 15:00:00 /2026-04-05/
[15:00:15] [CRITICAL] all tested parameters do not appear to be injectable.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Scanner Olusturma Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLMapScannerCreation:
    """Scanner olusturma testleri."""

    def test_create_with_path(self):
        """Belirtilen yol ile olusturma."""
        scanner = SQLMapScanner(sqlmap_path="/usr/bin/sqlmap")
        assert scanner.sqlmap_path == "/usr/bin/sqlmap"

    def test_default_timeout(self):
        """Varsayilan timeout degeri."""
        scanner = SQLMapScanner(sqlmap_path="/usr/bin/sqlmap")
        assert scanner.default_timeout == 300

    def test_custom_timeout(self):
        """Ozel timeout degeri."""
        scanner = SQLMapScanner(
            sqlmap_path="/usr/bin/sqlmap",
            default_timeout=600,
        )
        assert scanner.default_timeout == 600

    def test_parser_initialized(self):
        """Parser nesnesi baslatilmali."""
        scanner = SQLMapScanner(sqlmap_path="/usr/bin/sqlmap")
        assert scanner.parser is not None


# ─────────────────────────────────────────────────────────────────────────────
# Tarama Testleri (Mock)
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLMapScannerScan:
    """Mock SQLMap ile tarama testleri."""

    def setup_method(self):
        self.scanner = SQLMapScanner(sqlmap_path="/usr/bin/sqlmap")

    @patch("src.scanners.sqlmap_scanner.subprocess.run")
    def test_successful_scan_with_vulns(self, mock_run):
        """Basarili tarama — zafiyet bulunan senaryo."""
        mock_run.return_value = MagicMock(
            stdout=MOCK_VULNERABLE_STDOUT,
            stderr="",
            returncode=0,
        )

        config = SQLMapConfig(
            target_url="http://example.com/page?id=1",
            dbms="mysql",
        )
        result = self.scanner.scan(config)

        assert isinstance(result, ScanResult)
        assert result.status == ScanStatus.COMPLETED
        assert result.is_vulnerable
        assert result.vulnerability_count >= 2
        assert result.target_url == "http://example.com/page?id=1"

    @patch("src.scanners.sqlmap_scanner.subprocess.run")
    def test_successful_scan_no_vulns(self, mock_run):
        """Basarili tarama — zafiyet bulunamayan senaryo."""
        mock_run.return_value = MagicMock(
            stdout=MOCK_NO_VULN_STDOUT,
            stderr="",
            returncode=0,
        )

        config = SQLMapConfig(target_url="http://example.com/safe?q=test")
        result = self.scanner.scan(config)

        assert result.status == ScanStatus.COMPLETED
        assert not result.is_vulnerable
        assert result.vulnerability_count == 0

    @patch("src.scanners.sqlmap_scanner.subprocess.run")
    def test_scan_timeout(self, mock_run):
        """Tarama zaman asimi senaryosu."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="sqlmap", timeout=30)

        config = SQLMapConfig(target_url="http://example.com/slow?id=1")
        result = self.scanner.scan(config, timeout=30)

        assert result.status == ScanStatus.TIMEOUT
        assert "tamamlanamadi" in result.error_message

    def test_scan_without_sqlmap(self):
        """SQLMap bulunamadiginda hata firlatma."""
        scanner = SQLMapScanner(sqlmap_path=None)
        scanner.sqlmap_path = None  # Force None

        config = SQLMapConfig(target_url="http://example.com?id=1")

        with pytest.raises(SQLMapNotFoundError):
            scanner.scan(config)

    def test_scan_invalid_config(self):
        """Gecersiz yapilandirma ile tarama — ValueError."""
        config = SQLMapConfig(target_url="")  # Bos URL

        with pytest.raises(ValueError):
            self.scanner.scan(config)

    @patch("src.scanners.sqlmap_scanner.subprocess.run")
    def test_scan_result_has_timing(self, mock_run):
        """Tarama sonucunda zamanlama bilgisi olmali."""
        mock_run.return_value = MagicMock(
            stdout=MOCK_VULNERABLE_STDOUT,
            stderr="",
            returncode=0,
        )

        config = SQLMapConfig(target_url="http://example.com?id=1")
        result = self.scanner.scan(config)

        assert result.started_at is not None
        assert result.finished_at is not None
        assert result.duration_seconds is not None
        assert result.duration_seconds >= 0

    @patch("src.scanners.sqlmap_scanner.subprocess.run")
    def test_scan_result_has_command_line(self, mock_run):
        """Tarama sonucunda komut satiri bilgisi olmali."""
        mock_run.return_value = MagicMock(
            stdout=MOCK_VULNERABLE_STDOUT,
            stderr="",
            returncode=0,
        )

        config = SQLMapConfig(target_url="http://example.com?id=1")
        result = self.scanner.scan(config)

        assert result.command_line != ""


# ─────────────────────────────────────────────────────────────────────────────
# Raporlama Entegrasyon Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestScanResultReporting:
    """Tarama sonuclarinin raporlama modulune uyumulugu."""

    def setup_method(self):
        self.scanner = SQLMapScanner(sqlmap_path="/usr/bin/sqlmap")

    @patch("src.scanners.sqlmap_scanner.subprocess.run")
    def test_to_report_dict(self, mock_run):
        """report_dict formatinin dogrulugu."""
        mock_run.return_value = MagicMock(
            stdout=MOCK_VULNERABLE_STDOUT,
            stderr="",
            returncode=0,
        )

        config = SQLMapConfig(target_url="http://example.com?id=1")
        result = self.scanner.scan(config)
        report = result.to_report_dict()

        assert isinstance(report, dict)
        assert "target_url" in report
        assert "vulnerabilities" in report
        assert "summary" in report
        assert "is_vulnerable" in report
        assert report["is_vulnerable"] is True

    @patch("src.scanners.sqlmap_scanner.subprocess.run")
    def test_to_db_records(self, mock_run):
        """Veritabani kayit formatinin dogrulugu."""
        mock_run.return_value = MagicMock(
            stdout=MOCK_VULNERABLE_STDOUT,
            stderr="",
            returncode=0,
        )

        config = SQLMapConfig(target_url="http://example.com?id=1")
        result = self.scanner.scan(config)
        db_records = result.to_db_records()

        assert "scan" in db_records
        assert "vulnerabilities" in db_records
        assert "report" in db_records

        # SCANS tablosu uyumlulugu
        scan_record = db_records["scan"]
        assert "target_url" in scan_record
        assert "status" in scan_record

        # VULNERABILITIES tablosu uyumlulugu
        for vuln_record in db_records["vulnerabilities"]:
            assert "vuln_type" in vuln_record
            assert vuln_record["vuln_type"] == "SQLi"
            assert "severity" in vuln_record

        # REPORTS tablosu uyumlulugu
        report_record = db_records["report"]
        assert "summary" in report_record

    @patch("src.scanners.sqlmap_scanner.subprocess.run")
    def test_to_json(self, mock_run):
        """JSON ciktisinin dogrulugu."""
        mock_run.return_value = MagicMock(
            stdout=MOCK_VULNERABLE_STDOUT,
            stderr="",
            returncode=0,
        )

        config = SQLMapConfig(target_url="http://example.com?id=1")
        result = self.scanner.scan(config)
        json_output = result.to_json()

        import json
        parsed = json.loads(json_output)
        assert isinstance(parsed, dict)
        assert parsed["is_vulnerable"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Asenkron Tarama Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestAsyncScanning:
    """Asenkron tarama testleri."""

    def test_async_without_sqlmap(self):
        """SQLMap yokken asenkron tarama hatasi."""
        scanner = SQLMapScanner(sqlmap_path=None)
        scanner.sqlmap_path = None

        config = SQLMapConfig(target_url="http://example.com?id=1")

        with pytest.raises(SQLMapNotFoundError):
            scanner.scan_async(config)

    def test_get_status_not_found(self):
        """Var olmayan gorev durumu sorgusu."""
        scanner = SQLMapScanner(sqlmap_path="/usr/bin/sqlmap")
        status = scanner.get_scan_status("nonexistent-id")
        assert status["status"] == "not_found"

    def test_stop_nonexistent_scan(self):
        """Var olmayan taramayi durdurma."""
        scanner = SQLMapScanner(sqlmap_path="/usr/bin/sqlmap")
        result = scanner.stop_scan("nonexistent-id")
        assert result is False

    def test_get_result_nonexistent(self):
        """Var olmayan gorev sonucunu alma."""
        scanner = SQLMapScanner(sqlmap_path="/usr/bin/sqlmap")
        result = scanner.get_scan_result("nonexistent-id")
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# Context Manager Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestContextManager:
    """Context manager destegi testleri."""

    def test_context_manager(self):
        """with blogu ile kullanim."""
        with SQLMapScanner(sqlmap_path="/usr/bin/sqlmap") as scanner:
            assert scanner is not None
