"""
Veritabanı Modülü
==================

SQLite tabanlı veri katmanı. Nursena Karaduman'ın orijinal 5 tablolu şeması
kullanılır:

    USERS, SCAN_CONFIGS, SCANS, VULNERABILITIES, REPORTS

Düzeltilen Buglar (Nursena'nın BUG_RAPORU.md'sinden):
    BUG-001: Türkçe karakterli dosya adı → ASCII'ye çevrildi
    BUG-002: `tablolari_olustur()` import esnasında çalışıyordu → fonksiyon
             içine taşındı, sadece açık çağrıldığında çalışır
    BUG-003: SQL injection riski olan f-string sorguları → parametreli sorgulara
             çevrildi
"""

import sqlite3
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from contextlib import contextmanager

from .models import ScanResult, Vulnerability, ScanStatus


# Veritabanı dosya yolu (BUG-001 düzeltildi: ASCII isim)
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "siber_savascilar.db"
)


# ─────────────────────────────────────────────────────────────────────────────
# Şema Tanımları
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT,
    check_sqli INTEGER DEFAULT 1,
    check_xss INTEGER DEFAULT 1,
    check_ports INTEGER DEFAULT 1,
    check_misconfig INTEGER DEFAULT 1,
    check_sensitive_data INTEGER DEFAULT 1,
    check_access_control INTEGER DEFAULT 1,
    check_sqlmap INTEGER DEFAULT 0,
    check_custom_scenarios INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    config_id INTEGER,
    target_url TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    started_at TEXT,
    finished_at TEXT,
    duration_seconds REAL,
    modules_run TEXT,
    open_ports TEXT,
    error_message TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (config_id) REFERENCES scan_configs(id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    target TEXT,
    description TEXT,
    payload TEXT,
    evidence TEXT,
    parameter TEXT,
    cwe TEXT,
    remediation TEXT,
    details_json TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL UNIQUE,
    summary TEXT,
    html_path TEXT,
    json_path TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
"""


# ─────────────────────────────────────────────────────────────────────────────
# Veritabanı Yöneticisi
# ─────────────────────────────────────────────────────────────────────────────

class Database:
    """Tüm DB işlemlerini yöneten sınıf. Thread-safe bağlantı yönetimi."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.initialize()

    @contextmanager
    def connection(self):
        """Bağlantı açar, otomatik commit/rollback ve kapatma yapar."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self):
        """Şemayı oluşturur (idempotent)."""
        with self.connection() as conn:
            conn.executescript(SCHEMA_SQL)

    # ── SCANS ──────────────────────────────────────────────────────────────

    def create_scan(self, target_url: str, modules: List[str] = None) -> int:
        """Yeni bir tarama kaydı oluşturur, scan_id döndürür."""
        with self.connection() as conn:
            cursor = conn.execute(
                """INSERT INTO scans (target_url, status, started_at, modules_run)
                   VALUES (?, ?, ?, ?)""",
                (target_url, ScanStatus.RUNNING, datetime.now(timezone(timedelta(hours=3))).replace(tzinfo=None).isoformat(),
                 ",".join(modules or []))
            )
            return cursor.lastrowid

    def update_scan(self, scan_id: int, **fields):
        """Tarama kaydını günceller."""
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields.keys())
        with self.connection() as conn:
            conn.execute(
                f"UPDATE scans SET {cols} WHERE id = ?",
                list(fields.values()) + [scan_id]
            )

    def finish_scan(self, scan_result: ScanResult):
        """Bir taramayı sonlandırır ve sonuçları DB'ye yazar."""
        with self.connection() as conn:
            conn.execute(
                """UPDATE scans
                   SET status = ?, finished_at = ?, duration_seconds = ?,
                       open_ports = ?, error_message = ?, modules_run = ?
                   WHERE id = ?""",
                (
                    scan_result.status,
                    scan_result.finished_at.isoformat() if scan_result.finished_at else None,
                    scan_result.duration_seconds,
                    ",".join(map(str, scan_result.open_ports)),
                    scan_result.error_message,
                    ",".join(scan_result.modules_run),
                    scan_result.scan_id
                )
            )

            # Zafiyetleri yaz
            for vuln in scan_result.vulnerabilities:
                rec = vuln.to_db_record()
                conn.execute(
                    """INSERT INTO vulnerabilities
                       (scan_id, vuln_type, severity, target, description, payload,
                        evidence, parameter, cwe, remediation, details_json,
                        discovered_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_result.scan_id, rec["vuln_type"], rec["severity"],
                        rec["target"], rec["description"], rec["payload"],
                        rec["evidence"], rec["parameter"], rec["cwe"],
                        rec["remediation"], rec["details_json"], rec["discovered_at"]
                    )
                )

            # Rapor özetini yaz
            summary = scan_result.summary or scan_result.generate_summary()
            conn.execute(
                """INSERT OR REPLACE INTO reports (scan_id, summary)
                   VALUES (?, ?)""",
                (scan_result.scan_id, summary)
            )

    def update_report_paths(self, scan_id: int, html_path: str = None,
                            json_path: str = None):
        with self.connection() as conn:
            updates = []
            params = []
            if html_path:
                updates.append("html_path = ?")
                params.append(html_path)
            if json_path:
                updates.append("json_path = ?")
                params.append(json_path)
            if not updates:
                return
            params.append(scan_id)
            conn.execute(
                f"UPDATE reports SET {', '.join(updates)} WHERE scan_id = ?",
                params
            )

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            return dict(row) if row else None

    def get_vulnerabilities(self, scan_id: int) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY id",
                (scan_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_report(self, scan_id: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Son taramaları döndürür (en yeni önce)."""
        with self.connection() as conn:
            rows = conn.execute(
                """SELECT s.*,
                          (SELECT COUNT(*) FROM vulnerabilities v WHERE v.scan_id = s.id)
                          AS vuln_count
                   FROM scans s
                   ORDER BY s.id DESC
                   LIMIT ?""",
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Dashboard için özet istatistikler."""
        with self.connection() as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            critical = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'Critical'"
            ).fetchone()[0]
            high = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'High'"
            ).fetchone()[0]
            return {
                "total_scans": total_scans,
                "total_vulnerabilities": total_vulns,
                "critical_count": critical,
                "high_count": high,
            }

    def delete_scan(self, scan_id: int):
        """Bir taramayı ve ilişkili tüm kayıtları siler."""
        with self.connection() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


# Modül seviyesinde singleton
_default_db: Optional[Database] = None


def get_db() -> Database:
    """Varsayılan veritabanı örneğini döndürür (lazy initialization)."""
    global _default_db
    if _default_db is None:
        _default_db = Database()
    return _default_db
