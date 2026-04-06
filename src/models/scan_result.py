"""
Siber Savascilar — Veri Modelleri
==================================

SQLMap tarama sonuclarini temsil eden veri modelleri.
Nursena'nin VULNERABILITIES ve SCANS tablosuna uyumlu olarak tasarlanmistir.

Veritabani Uyumu:
    - Vulnerability → VULNERABILITIES tablosu (vuln_type, severity)
    - ScanResult → SCANS tablosu (target_url, status, started_at, finished_at)
                 + REPORTS tablosu (summary)
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Any
import json


# ─────────────────────────────────────────────────────────────────────────────
# Sabitler
# ─────────────────────────────────────────────────────────────────────────────

class Severity:
    """Zafiyet kritiklik seviyeleri — OWASP risk derecelendirmesine uygun."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    _order = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Informational": 0,
    }

    @classmethod
    def compare(cls, a: str, b: str) -> int:
        """Iki severity degerini karsilastirir. Pozitif: a daha kritik."""
        return cls._order.get(a, -1) - cls._order.get(b, -1)

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Gecerli bir severity degeri mi kontrolu."""
        return value in cls._order


class ScanStatus:
    """Tarama durum sabitleri — SCANS tablosundaki status alani ile uyumlu."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


# ─────────────────────────────────────────────────────────────────────────────
# Zafiyet Modeli
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """
    Tek bir SQL injection zafiyetini temsil eder.
    
    VULNERABILITIES tablosuna esleme:
        vuln_type  → "SQLi"
        severity   → "Critical" | "High" | "Medium" | "Low"
    
    Attributes:
        vuln_type:   Zafiyet turu. SQLMap modulu icin her zaman "SQLi".
        severity:    Kritiklik seviyesi (Severity sinifindaki sabitler).
        parameter:   Zafiyete sahip HTTP parametresi (orn: "id", "username").
        technique:   Kullanilan SQL injection teknigi.
        injection_type: Injection noktasi tipi (GET, POST, Cookie, Header).
        payload:     SQLMap'in kullandigi test payload'u.
        dbms:        Tespit edilen veritabani yonetim sistemi.
        dbms_version: Veritabani surumu (tespit edilebildiyse).
        title:       SQLMap'in injection basligi.
        details:     Ek detaylar (serbest format sozluk).
    """

    vuln_type: str = "SQLi"
    severity: str = Severity.HIGH
    parameter: str = ""
    technique: str = ""
    injection_type: str = ""
    payload: str = ""
    dbms: str = ""
    dbms_version: str = ""
    title: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_db_record(self) -> Dict[str, Any]:
        """
        VULNERABILITIES tablosuna eklenecek formatta sozluk doner.
        
        Returns:
            {
                "vuln_type": "SQLi",
                "severity": "High",
                "parameter": "id",
                "technique": "Boolean-based blind",
                "payload": "...",
                "dbms": "MySQL",
                "details_json": "{...}"
            }
        """
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "parameter": self.parameter,
            "technique": self.technique,
            "injection_type": self.injection_type,
            "payload": self.payload,
            "dbms": self.dbms,
            "dbms_version": self.dbms_version,
            "title": self.title,
            "details_json": json.dumps(self.details, ensure_ascii=False),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Tum alanlari sozluk olarak doner."""
        return asdict(self)

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.vuln_type} — "
            f"Parametre: {self.parameter}, "
            f"Teknik: {self.technique}, "
            f"DBMS: {self.dbms}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Tarama Sonucu Modeli
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    Tam bir SQLMap tarama sonucunu temsil eder.
    
    SCANS tablosuna esleme:
        target_url   → target_url
        status       → status
        started_at   → started_at
        finished_at  → finished_at
    
    REPORTS tablosuna esleme:
        summary      → summary
    
    Attributes:
        target_url:      Taranan hedef URL.
        started_at:      Tarama baslangic zamani.
        finished_at:     Tarama bitis zamani.
        status:          Tarama durumu (ScanStatus sabitleri).
        vulnerabilities: Bulunan zafiyet listesi.
        scan_config:     Kullanilan tarama yapilandirmasi.
        raw_output:      Ham SQLMap konsol ciktisi.
        summary:         Otomatik olusturulan tarama ozeti.
        error_message:   Hata durumunda hata mesaji.
        sqlmap_version:  Kullanilan SQLMap surumu.
        command_line:    Calistirilan SQLMap komutu.
    """

    target_url: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: str = ScanStatus.PENDING
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_config: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    summary: str = ""
    error_message: str = ""
    sqlmap_version: str = ""
    command_line: str = ""

    # ── Hesaplanan ozellikler ──

    @property
    def duration_seconds(self) -> Optional[float]:
        """Tarama suresini saniye olarak doner."""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def is_vulnerable(self) -> bool:
        """Hedef sistem SQL injection zafiyetine sahip mi?"""
        return len(self.vulnerabilities) > 0

    @property
    def vulnerability_count(self) -> int:
        """Bulunan zafiyet sayisi."""
        return len(self.vulnerabilities)

    @property
    def highest_severity(self) -> Optional[str]:
        """En yuksek kritiklik seviyesini doner."""
        if not self.vulnerabilities:
            return None
        return max(
            self.vulnerabilities,
            key=lambda v: Severity._order.get(v.severity, -1)
        ).severity

    @property
    def affected_parameters(self) -> List[str]:
        """Etkilenen parametre isimlerinin benzersiz listesi."""
        return list(set(v.parameter for v in self.vulnerabilities if v.parameter))

    @property
    def detected_dbms_list(self) -> List[str]:
        """Tespit edilen DBMS'lerin benzersiz listesi."""
        return list(set(v.dbms for v in self.vulnerabilities if v.dbms))

    # ── Donusum metodlari ──

    def generate_summary(self) -> str:
        """
        Tarama sonucuna dayali otomatik Turkce ozet olusturur.
        REPORTS tablosundaki 'summary' alani icin kullanilir.
        """
        if self.status == ScanStatus.ERROR:
            return f"Tarama hata ile sonuclandi: {self.error_message}"

        if self.status == ScanStatus.TIMEOUT:
            return "Tarama zaman asimina ugradi."

        if not self.is_vulnerable:
            duration_info = ""
            if self.duration_seconds is not None:
                duration_info = f" Tarama suresi: {self.duration_seconds:.1f} saniye."
            return (
                f"{self.target_url} hedefinde SQL injection zafiyeti tespit edilmedi."
                f"{duration_info}"
            )

        # Zafiyet bulundu — detayli ozet
        vuln_count = self.vulnerability_count
        params = ", ".join(self.affected_parameters)
        dbms_info = ", ".join(self.detected_dbms_list) or "Bilinmiyor"
        highest = self.highest_severity

        lines = [
            f"🔴 {self.target_url} hedefinde {vuln_count} adet SQL injection zafiyeti tespit edildi.",
            f"",
            f"📊 En yuksek kritiklik seviyesi: {highest}",
            f"🎯 Etkilenen parametreler: {params}",
            f"🗄️  Veritabani sistemi: {dbms_info}",
            f"⏱️  Tarama suresi: {self.duration_seconds:.1f} saniye" if self.duration_seconds else "",
            f"",
            f"Tespit edilen zafiyetler:",
        ]

        for i, vuln in enumerate(self.vulnerabilities, 1):
            lines.append(
                f"  {i}. [{vuln.severity}] {vuln.parameter} — {vuln.technique}"
            )

        self.summary = "\n".join(line for line in lines if line is not None)
        return self.summary

    def to_report_dict(self) -> Dict[str, Any]:
        """
        Raporlama modulune aktarilacak formatta sozluk doner.
        
        Returns:
            Raporlama modulunun kullanabilecegi kapsamli sozluk.
        """
        return {
            "target_url": self.target_url,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "is_vulnerable": self.is_vulnerable,
            "vulnerability_count": self.vulnerability_count,
            "highest_severity": self.highest_severity,
            "affected_parameters": self.affected_parameters,
            "detected_dbms": self.detected_dbms_list,
            "summary": self.summary or self.generate_summary(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_config": self.scan_config,
            "sqlmap_version": self.sqlmap_version,
            "command_line": self.command_line,
        }

    def to_db_records(self) -> Dict[str, Any]:
        """
        Veritabani tablolarina uyumlu ayristirilmis kayitlar doner.
        
        Returns:
            {
                "scan": {...},               # SCANS tablosu
                "vulnerabilities": [...],     # VULNERABILITIES tablosu
                "report": {...}               # REPORTS tablosu
            }
        """
        return {
            "scan": {
                "target_url": self.target_url,
                "status": self.status,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            },
            "vulnerabilities": [v.to_db_record() for v in self.vulnerabilities],
            "report": {
                "summary": self.summary or self.generate_summary(),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Tarama sonucunu JSON formatinda doner."""
        return json.dumps(
            self.to_report_dict(),
            indent=indent,
            ensure_ascii=False,
            default=str,
        )

    def __str__(self) -> str:
        status_emoji = {
            ScanStatus.COMPLETED: "✅",
            ScanStatus.ERROR: "❌",
            ScanStatus.TIMEOUT: "⏰",
            ScanStatus.RUNNING: "🔄",
            ScanStatus.PENDING: "⏳",
            ScanStatus.CANCELLED: "🚫",
        }
        emoji = status_emoji.get(self.status, "❓")

        return (
            f"{emoji} SQLMap Tarama Sonucu: {self.target_url}\n"
            f"   Durum: {self.status} | "
            f"Zafiyet: {self.vulnerability_count} adet | "
            f"En yuksek: {self.highest_severity or 'N/A'}"
        )
