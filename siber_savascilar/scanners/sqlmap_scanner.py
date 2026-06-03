"""
SQLMap Entegrasyonu (Wrapper)
==============================

M. Sefa Kozan'ın src/scanners/sqlmap_scanner.py modülünden basitleştirilmiş
wrapper. Tam Sefa kodu 790 satır olduğundan, demoda kullanıma uygun pratik
bir versiyon hazırlandı — orijinal kod 'legacy/sefa/' altında muhafaza edilir.

Bu modül sistemde 'sqlmap' binary'si varsa onu subprocess olarak çağırır.
Yoksa sqli_scanner.py modülüne (kendi SQLi tarayıcımız) düşer.
"""

import os
import shutil
import subprocess
import tempfile
import re
from typing import List

from .base import BaseScanner
from ..core.models import Vulnerability, Severity, VulnType


# Output içinde SQLMap'in bulguyu raporladığı pattern
SQLMAP_INJECTABLE_PATTERN = re.compile(
    r"Parameter:\s*(\S+)\s*\(([^)]+)\)", re.MULTILINE
)
SQLMAP_DBMS_PATTERN = re.compile(
    r"back-end DBMS:\s*(.+?)(?:\s|$)", re.IGNORECASE
)


class SQLMapScanner(BaseScanner):
    """SQLMap binary wrapper."""

    name = "sqlmap_scanner"
    description = "SQLMap subprocess wrapper (binary varsa)"

    def __init__(self, timeout: int = 120, level: int = 1, risk: int = 1,
                 verbose: bool = True):
        super().__init__(timeout=timeout, verbose=verbose)
        self.level = max(1, min(level, 5))
        self.risk = max(1, min(risk, 3))
        self._sqlmap_path = shutil.which("sqlmap")

    def is_available(self) -> bool:
        return self._sqlmap_path is not None

    def scan(self, target: str) -> List[Vulnerability]:
        if not self.is_available():
            self.log("SQLMap binary bulunamadı, pas geçiliyor", "warning")
            return []

        self.log(f"SQLMap taraması başlıyor: {target}")
        self.log(f"  (Bu işlem 1-5 dakika sürebilir, level={self.level} risk={self.risk})")

        with tempfile.TemporaryDirectory(prefix="sqlmap_") as tmpdir:
            cmd = [
                self._sqlmap_path,
                "-u", target,
                "--batch",                # Etkileşim yok
                "--level", str(self.level),
                "--risk", str(self.risk),
                "--output-dir", tmpdir,
                "--disable-coloring",
                "--flush-session",
                "--threads", "4",
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=False,
                )
                return self._parse_output(result.stdout, target)

            except subprocess.TimeoutExpired:
                self.log("SQLMap zaman aşımına uğradı", "warning")
                return []
            except Exception as e:
                self.log(f"SQLMap hatası: {e}", "error")
                return []

    def _parse_output(self, output: str, target: str) -> List[Vulnerability]:
        """SQLMap çıktısından zafiyet listesi çıkarır."""
        vulns = []

        # Parametre / teknik eşleşmeleri
        matches = SQLMAP_INJECTABLE_PATTERN.findall(output)

        dbms_match = SQLMAP_DBMS_PATTERN.search(output)
        dbms = dbms_match.group(1) if dbms_match else ""

        for param, technique_type in matches:
            self.log(f"  [!] SQLMap zafiyet bulgusu: {param} ({technique_type})")
            vulns.append(Vulnerability(
                vuln_type=VulnType.SQLI,
                severity=Severity.CRITICAL,
                target=target,
                parameter=param,
                description=f"SQLMap tarafından doğrulanmış SQL injection: "
                            f"{param} parametresi.",
                evidence=f"Injection tipi: {technique_type} | DBMS: {dbms or 'bilinmiyor'}",
                cwe="CWE-89",
                remediation="Parametreli sorgular (prepared statements) kullanın. "
                            "ORM kullanıyorsanız raw query'lerden kaçının.",
                details={
                    "tool": "sqlmap",
                    "technique": technique_type,
                    "dbms": dbms,
                    "level": self.level,
                    "risk": self.risk,
                },
            ))

        return vulns
