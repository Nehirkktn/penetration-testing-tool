"""
Sensitive Data Exposure Tarayıcı (OWASP A02:2021)
====================================================

Nursena Karaduman'ın sensitive_data_scanner.py'sinden adapte edilmiştir.

HTTP üzerinden veri iletimi, sayfa içinde sızmış API anahtarları, e-posta
adresleri, JWT token'ları gibi hassas verilerin varlığını test eder.
"""

import re
import requests
from typing import List

from .base import BaseScanner
from ..core.models import Vulnerability, Severity, VulnType


# Hassas veri regex'leri
SENSITIVE_PATTERNS = [
    ("E-posta adresi", Severity.LOW,
     re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")),
    ("API Key (genel)", Severity.HIGH,
     re.compile(r"(api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['\"]?\w{16,}",
                re.IGNORECASE)),
    ("AWS Access Key", Severity.CRITICAL,
     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", Severity.HIGH,
     re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("JWT Token", Severity.HIGH,
     re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Olası şifre", Severity.HIGH,
     re.compile(r"(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"<>]{4,}",
                re.IGNORECASE)),
    ("Kredi kartı numarası", Severity.CRITICAL,
     re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("Dahili IP adresi", Severity.LOW,
     re.compile(r"\b(192\.168|10\.\d{1,3}|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
    ("Private Key başlığı", Severity.CRITICAL,
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
]

# Taranacak yaygın sayfalar
PAGES_TO_CHECK = ["/", "/login", "/register", "/api", "/api/users", "/contact"]


class SensitiveDataScanner(BaseScanner):
    """Hassas veri sızıntısı tarayıcısı."""

    name = "sensitive_data_scanner"
    description = "OWASP A02: Sensitive Data Exposure tespit"

    MAX_CONSECUTIVE_FAILURES = 3

    def __init__(self, timeout: int = 5, verbose: bool = True):
        super().__init__(timeout=timeout, verbose=verbose)
        self._consecutive_failures = 0
        self._aborted = False

    def scan(self, target: str) -> List[Vulnerability]:
        self.log(f"Sensitive Data taraması başlıyor: {target}")
        vulns = []

        target = target.rstrip("/")

        # 1. Protokol kontrolü
        if target.startswith("http://"):
            self.log("  [!] Site HTTP kullanıyor")
            vulns.append(Vulnerability(
                vuln_type=VulnType.SENSITIVE_DATA,
                severity=Severity.MEDIUM,
                target=target,
                description="Site şifresiz HTTP üzerinden çalışıyor. "
                            "Veriler clear-text olarak iletiliyor.",
                evidence="URL şeması: http://",
                cwe="CWE-319",
                remediation="HTTPS'e geçin ve HTTP isteklerini HTTPS'e yönlendirin. "
                            "HSTS başlığı tanımlayın.",
                details={"protocol": "http"},
            ))

        # 2. Sayfalarda hassas veri arama
        for page in PAGES_TO_CHECK:
            if self._aborted:
                break
            url = target + page
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                self._consecutive_failures = 0
                if response.status_code != 200:
                    continue

                for name, severity, pattern in SENSITIVE_PATTERNS:
                    matches = pattern.findall(response.text)
                    if matches:
                        # İlk eşleşmeyi göster, hepsini değil (gizlilik)
                        example = str(matches[0])[:80]
                        self.log(f"  [!] {name} sızıntısı: {page}")
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.SENSITIVE_DATA,
                            severity=severity,
                            target=url,
                            description=f"{name} sayfa içeriğinde tespit edildi: {page}",
                            evidence=f"Örnek: {example}",
                            cwe="CWE-200",
                            remediation=f"Hassas verileri client'a göndermeyin. "
                                        f"API anahtarları sunucu tarafında tutulmalı, "
                                        f"şifreler hash'lenmiş şekilde saklanmalı.",
                            details={"page": page, "pattern": name,
                                     "match_count": len(matches)},
                        ))

            except requests.RequestException:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                    self._aborted = True
                    self.log(f"Üst üste hata, tarama durduruluyor", "warning")
                    break
                continue

        return vulns
