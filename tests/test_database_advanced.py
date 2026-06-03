"""Database modülü için ileri seviye testler."""

import os
import tempfile
from datetime import datetime
import pytest

from siber_savascilar.core.database import Database, SCHEMA_SQL
from siber_savascilar.core.models import (
    ScanResult, Vulnerability, Severity, ScanStatus, VulnType
)


@pytest.fixture
def db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        yield Database(db_path)
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


# ─────────────────────────────────────────────────────────────────────────
# Schema doğrulama
# ─────────────────────────────────────────────────────────────────────────

class TestSchema:
    def test_all_required_tables_exist(self, db):
        with db.connection() as conn:
            tables = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        required = {"users", "scan_configs", "scans",
                    "vulnerabilities", "reports"}
        assert required.issubset(tables)

    def test_indexes_created(self, db):
        with db.connection() as conn:
            indexes = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}
        # Bizim tanımladığımız indexler
        assert "idx_vulns_scan" in indexes
        assert "idx_vulns_severity" in indexes

    def test_foreign_keys_enabled(self, db):
        with db.connection() as conn:
            result = conn.execute("PRAGMA foreign_keys").fetchone()
            assert result[0] == 1


# ─────────────────────────────────────────────────────────────────────────
# Scan lifecycle
# ─────────────────────────────────────────────────────────────────────────

class TestScanLifecycle:
    def test_create_returns_valid_id(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        assert scan_id is not None
        assert scan_id > 0

    def test_create_unique_ids(self, db):
        id1 = db.create_scan("http://t.com", ["sqli"])
        id2 = db.create_scan("http://t.com", ["sqli"])
        assert id1 != id2

    def test_create_records_modules(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli", "xss", "misconfig"])
        scan = db.get_scan(scan_id)
        assert "sqli" in scan["modules_run"]
        assert "xss" in scan["modules_run"]
        assert "misconfig" in scan["modules_run"]

    def test_create_initial_status_is_running(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        scan = db.get_scan(scan_id)
        assert scan["status"] == ScanStatus.RUNNING

    def test_update_scan(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        db.update_scan(scan_id, status=ScanStatus.COMPLETED)
        scan = db.get_scan(scan_id)
        assert scan["status"] == ScanStatus.COMPLETED

    def test_update_with_no_fields_is_noop(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        db.update_scan(scan_id)  # Boş — hata vermemeli
        scan = db.get_scan(scan_id)
        assert scan is not None


# ─────────────────────────────────────────────────────────────────────────
# Finish scan
# ─────────────────────────────────────────────────────────────────────────

class TestFinishScan:
    def _build_result(self, scan_id, num_vulns=3):
        r = ScanResult(
            scan_id=scan_id,
            target_url="http://t.com",
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(),
            finished_at=datetime.now(),
        )
        for _ in range(num_vulns):
            r.add_vulnerability(Vulnerability(
                vuln_type=VulnType.SQLI,
                severity=Severity.HIGH,
                target="http://t.com",
                description="Test",
            ))
        return r

    def test_finish_writes_status(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        r = self._build_result(scan_id, num_vulns=0)
        db.finish_scan(r)
        assert db.get_scan(scan_id)["status"] == ScanStatus.COMPLETED

    def test_finish_writes_vulnerabilities(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        r = self._build_result(scan_id, num_vulns=3)
        db.finish_scan(r)
        vulns = db.get_vulnerabilities(scan_id)
        assert len(vulns) == 3

    def test_finish_writes_open_ports(self, db):
        scan_id = db.create_scan("http://t.com", ["ports"])
        r = self._build_result(scan_id, num_vulns=0)
        r.open_ports = [80, 443, 8080]
        db.finish_scan(r)
        scan = db.get_scan(scan_id)
        assert "80" in scan["open_ports"]

    def test_finish_creates_report_record(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        r = self._build_result(scan_id, num_vulns=1)
        db.finish_scan(r)
        report = db.get_report(scan_id)
        assert report is not None
        assert "summary" in report


# ─────────────────────────────────────────────────────────────────────────
# Report paths
# ─────────────────────────────────────────────────────────────────────────

class TestReportPaths:
    def test_update_html_path(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        r = ScanResult(scan_id=scan_id, target_url="http://t.com",
                       status=ScanStatus.COMPLETED,
                       started_at=datetime.now(), finished_at=datetime.now())
        db.finish_scan(r)
        db.update_report_paths(scan_id, html_path="/tmp/report.html")
        report = db.get_report(scan_id)
        assert report["html_path"] == "/tmp/report.html"

    def test_update_both_paths(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        r = ScanResult(scan_id=scan_id, target_url="http://t.com",
                       status=ScanStatus.COMPLETED,
                       started_at=datetime.now(), finished_at=datetime.now())
        db.finish_scan(r)
        db.update_report_paths(scan_id, html_path="/a.html", json_path="/b.json")
        report = db.get_report(scan_id)
        assert report["html_path"] == "/a.html"
        assert report["json_path"] == "/b.json"

    def test_update_with_empty_args_no_change(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        r = ScanResult(scan_id=scan_id, target_url="http://t.com",
                       status=ScanStatus.COMPLETED,
                       started_at=datetime.now(), finished_at=datetime.now())
        db.finish_scan(r)
        db.update_report_paths(scan_id)  # Hiçbir alan değil
        # Hata vermemeli


# ─────────────────────────────────────────────────────────────────────────
# Concurrency / connection
# ─────────────────────────────────────────────────────────────────────────

class TestConnection:
    def test_connection_context_commits(self, db):
        with db.connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("test_user", "hash")
            )
        # Yeni bağlantıda da görünmeli
        with db.connection() as conn:
            r = conn.execute("SELECT * FROM users WHERE username='test_user'").fetchone()
            assert r is not None

    def test_connection_rolls_back_on_exception(self, db):
        with pytest.raises(Exception):
            with db.connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    ("rollback_test", "hash")
                )
                raise RuntimeError("force rollback")
        # Rollback olmuş olmalı
        with db.connection() as conn:
            r = conn.execute(
                "SELECT * FROM users WHERE username='rollback_test'"
            ).fetchone()
            assert r is None


# ─────────────────────────────────────────────────────────────────────────
# Statistics
# ─────────────────────────────────────────────────────────────────────────

class TestStatistics:
    def test_stats_with_data(self, db):
        scan_id = db.create_scan("http://t.com", ["sqli"])
        r = ScanResult(scan_id=scan_id, target_url="http://t.com",
                       status=ScanStatus.COMPLETED,
                       started_at=datetime.now(), finished_at=datetime.now())
        r.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
        r.add_vulnerability(Vulnerability(severity=Severity.CRITICAL))
        r.add_vulnerability(Vulnerability(severity=Severity.HIGH))
        r.add_vulnerability(Vulnerability(severity=Severity.LOW))
        db.finish_scan(r)

        stats = db.get_stats()
        assert stats["total_scans"] == 1
        assert stats["total_vulnerabilities"] == 4
        assert stats["critical_count"] == 2
        assert stats["high_count"] == 1


# ─────────────────────────────────────────────────────────────────────────
# Türkçe karakter testi (Bug-002 doğrulaması)
# ─────────────────────────────────────────────────────────────────────────

class TestTurkishCharBugFix:
    def test_db_path_has_no_turkish_chars(self, db):
        """siber_savascilar.db ASCII isimli olmalı."""
        assert "ı" not in db.db_path
        assert "ç" not in db.db_path
        assert "ş" not in db.db_path
