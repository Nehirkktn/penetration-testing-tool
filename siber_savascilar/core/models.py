"""
Veri Modelleri
==============

Tüm tarayıcı modüllerinin döndüreceği ortak veri yapıları.

Sefa Kozan'ın orijinal `ScanResult` ve `Vulnerability` modeli temel alınmış,
sadece SQLMap'e özel olmaktan çıkarılıp tüm tarayıcılar için genelleştirilmiştir.

Veritabanı eşlemesi (Nursena Karaduman'ın 5 tablolu şeması):
    Vulnerability → VULNERABILITIES tablosu
    ScanResult    → SCANS + REPORTS tabloları
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Any
import json


# ─────────────────────────────────────────────────────────────────────────────
# Sabitler
# ─────────────────────────────────────────────────────────────────────────────

class Severity:
    """OWASP risk derecelendirmesine uygun kritiklik seviyeleri."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    _order = {
        "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0,
    }

    _colors = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#2563eb",
        "Informational": "#6b7280",
    }

    @classmethod
    def compare(cls, a: str, b: str) -> int:
        return cls._order.get(a, -1) - cls._order.get(b, -1)

    @classmethod
    def color(cls, severity: str) -> str:
        return cls._colors.get(severity, "#6b7280")

    @classmethod
    def is_valid(cls, value: str) -> bool:
        return value in cls._order


class ScanStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class VulnType:
    """OWASP Top 10 (2021) ve diğer yaygın zafiyet türleri."""
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    BROKEN_ACCESS = "Broken Access Control"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    OPEN_PORT = "Open Port / Service Exposure"
    CUSTOM_SCENARIO = "Custom Scenario Match"
    IDOR = "Insecure Direct Object Reference"


# ─────────────────────────────────────────────────────────────────────────────
# Zafiyet Modeli
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """
    Tek bir güvenlik açığını temsil eden veri modeli.

    Tüm tarayıcılar (SQLi, XSS, Port, Misconfig, Sensitive Data, Access Control,
    SQLMap, YAML senaryo) bu modeli döndürür.
    """

    vuln_type: str = ""
    severity: str = Severity.MEDIUM
    target: str = ""
    description: str = ""
    payload: str = ""
    evidence: str = ""
    parameter: str = ""
    cwe: str = ""
    remediation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    discovered_at: Optional[datetime] = None

    def __post_init__(self):
        if self.discovered_at is None:
            from datetime import timezone, timedelta
            self.discovered_at = datetime.now(timezone(timedelta(hours=3))).replace(tzinfo=None)

    def to_db_record(self) -> Dict[str, Any]:
        """VULNERABILITIES tablosuna uygun dict döndürür."""
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "target": self.target,
            "description": self.description,
            "payload": self.payload,
            "evidence": self.evidence,
            "parameter": self.parameter,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "details_json": json.dumps(self.details, ensure_ascii=False, default=str),
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d.get("discovered_at"):
            d["discovered_at"] = self.discovered_at.isoformat()
        return d

    def __str__(self) -> str:
        return f"[{self.severity}] {self.vuln_type} — {self.description}"


# ─────────────────────────────────────────────────────────────────────────────
# Tarama Sonucu Modeli
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Tek bir tarama oturumunun tüm sonuçlarını taşıyan model."""

    scan_id: Optional[int] = None
    target_url: str = ""
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: str = ScanStatus.PENDING
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    scan_config: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    summary: str = ""
    error_message: str = ""
    modules_run: List[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def severity_breakdown(self) -> Dict[str, int]:
        breakdown = {
            Severity.CRITICAL: 0, Severity.HIGH: 0,
            Severity.MEDIUM: 0, Severity.LOW: 0, Severity.INFO: 0,
        }
        for v in self.vulnerabilities:
            if v.severity in breakdown:
                breakdown[v.severity] += 1
        return breakdown

    @property
    def highest_severity(self) -> Optional[str]:
        if not self.vulnerabilities:
            return None
        return max(
            self.vulnerabilities,
            key=lambda v: Severity._order.get(v.severity, -1)
        ).severity

    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)

    def add_vulnerabilities(self, vulns: List[Vulnerability]):
        self.vulnerabilities.extend(vulns)

    def generate_summary(self) -> str:
        """Otomatik Türkçe özet oluşturur (raporlama için)."""
        if self.status == ScanStatus.ERROR:
            return f"Tarama hata ile sonuçlandı: {self.error_message}"
        if self.status == ScanStatus.TIMEOUT:
            return "Tarama zaman aşımına uğradı."

        if not self.is_vulnerable:
            d = f" Süre: {self.duration_seconds:.1f}sn." if self.duration_seconds else ""
            return f"{self.target_url} hedefinde herhangi bir zafiyet tespit edilmedi.{d}"

        brk = self.severity_breakdown
        lines = [
            f"{self.target_url} hedefinde {self.vulnerability_count} adet zafiyet tespit edildi.",
            f"Kritik: {brk[Severity.CRITICAL]} | Yüksek: {brk[Severity.HIGH]} | "
            f"Orta: {brk[Severity.MEDIUM]} | Düşük: {brk[Severity.LOW]}",
            f"Çalıştırılan modüller: {', '.join(self.modules_run)}",
        ]
        if self.duration_seconds:
            lines.append(f"Tarama süresi: {self.duration_seconds:.1f} saniye")
        self.summary = "\n".join(lines)
        return self.summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "is_vulnerable": self.is_vulnerable,
            "vulnerability_count": self.vulnerability_count,
            "highest_severity": self.highest_severity,
            "severity_breakdown": self.severity_breakdown,
            "open_ports": self.open_ports,
            "modules_run": self.modules_run,
            "summary": self.summary or self.generate_summary(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scan_config": self.scan_config,
            "error_message": self.error_message,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)

    def __str__(self) -> str:
        return (
            f"ScanResult(target={self.target_url}, status={self.status}, "
            f"vulns={self.vulnerability_count})"
        )
