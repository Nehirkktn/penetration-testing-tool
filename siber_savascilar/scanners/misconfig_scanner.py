"""
Security Misconfiguration Tarayıcı (OWASP A05:2021)
=====================================================

Nursena Karaduman'ın misconfig_scanner.py'sinden adapte edilmiştir.
Açık dizin listeleme, hassas dosya ifşası, eksik güvenlik başlıkları,
hata mesajı sızıntısı testleri yapar.
"""

import requests
from typing import List

from .base import BaseScanner
from ..core.models import Vulnerability, Severity, VulnType


# Test edilecek hassas dosya yolları
SENSITIVE_FILES = [
    "/.env", "/.git/config", "/.git/HEAD",
    "/config.php", "/config.yml", "/config.json", "/wp-config.php",
    "/backup.zip", "/backup.sql", "/database.sql", "/dump.sql",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/server-status",
    "/admin", "/phpinfo.php", "/info.php",
]

# Açık dizin listeleme için yaygın yollar
DIRECTORY_LISTING_PATHS = [
    "/uploads/", "/files/", "/backup/", "/logs/", "/tmp/",
    "/static/", "/assets/", "/images/", "/data/",
]

# Hassas dosya içerikleri için kelime imzaları
SENSITIVE_CONTENT_KEYWORDS = [
    "DB_PASSWORD", "DB_USER", "APP_KEY", "SECRET_KEY",
    "API_KEY", "AWS_ACCESS_KEY", "PRIVATE_KEY",
    "<?php", "mysql_connect", "<DefaultDocument>",
]

# Olması beklenen güvenlik başlıkları
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "HSTS başlığı eksik. HTTPS bağlantısı zorlanmıyor.",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains ekleyin."
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "X-Content-Type-Options başlığı eksik. MIME sniffing saldırılarına açık.",
        "X-Content-Type-Options: nosniff ekleyin."
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "X-Frame-Options başlığı eksik. Clickjacking saldırılarına açık.",
        "X-Frame-Options: DENY veya SAMEORIGIN ekleyin."
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "CSP başlığı eksik. XSS koruması zayıf.",
        "Content-Security-Policy: default-src 'self'; benzeri bir politika tanımlayın."
    ),
}


class MisconfigScanner(BaseScanner):
    """Yapılandırma hataları tarayıcısı."""

    name = "misconfig_scanner"
    description = "OWASP A05: Security Misconfiguration tespit"

    MAX_CONSECUTIVE_FAILURES = 4

    def __init__(self, timeout: int = 5, verbose: bool = True):
        super().__init__(timeout=timeout, verbose=verbose)
        self._consecutive_failures = 0
        self._aborted = False

    def scan(self, target: str) -> List[Vulnerability]:
        self.log(f"Misconfig taraması başlıyor: {target}")
        vulns = []

        target = target.rstrip("/")

        vulns.extend(self._check_security_headers(target))
        if not self._aborted:
            vulns.extend(self._check_sensitive_files(target))
        if not self._aborted:
            vulns.extend(self._check_directory_listing(target))

        return vulns

    def _check_security_headers(self, target: str) -> List[Vulnerability]:
        vulns = []
        try:
            response = requests.get(target, timeout=self.timeout, verify=False,
                                    allow_redirects=True)
            headers = {k.lower(): v for k, v in response.headers.items()}

            for header, (severity, desc, fix) in SECURITY_HEADERS.items():
                if header.lower() not in headers:
                    self.log(f"  [!] Eksik başlık: {header}")
                    vulns.append(Vulnerability(
                        vuln_type=VulnType.SECURITY_MISCONFIG,
                        severity=severity,
                        target=target,
                        description=desc,
                        evidence=f"Eksik HTTP başlığı: {header}",
                        cwe="CWE-693",
                        remediation=fix,
                        details={"missing_header": header},
                    ))
        except requests.RequestException as e:
            self.log(f"  Bağlantı hatası: {e}", "warning")
        return vulns

    def _check_sensitive_files(self, target: str) -> List[Vulnerability]:
        vulns = []
        for path in SENSITIVE_FILES:
            if self._aborted:
                break
            url = target + path
            try:
                response = requests.get(url, timeout=self.timeout, verify=False,
                                        allow_redirects=False)
                self._consecutive_failures = 0
                if response.status_code == 200 and len(response.text) > 0:
                    # İçerikte hassas anahtar kelime var mı?
                    found = [kw for kw in SENSITIVE_CONTENT_KEYWORDS
                             if kw.lower() in response.text.lower()]

                    if found:
                        self.log(f"  [!] Hassas dosya ifşa: {path} → {found}")
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.SECURITY_MISCONFIG,
                            severity=Severity.CRITICAL,
                            target=url,
                            description=f"Hassas yapılandırma dosyası erişilebilir: {path}",
                            evidence=f"İçerikte tespit edilen anahtarlar: {', '.join(found)}",
                            cwe="CWE-538",
                            remediation=f"{path} dosyasına web sunucusu üzerinden "
                                        f"erişimi engelleyin. .env gibi dosyaları "
                                        f"web kök dizini dışına taşıyın.",
                            details={"path": path, "keywords": found},
                        ))
                    elif path in ["/admin", "/phpinfo.php", "/info.php",
                                  "/server-status"]:
                        # Bu dosyaların kendisi varsa zaten zafiyettir
                        self.log(f"  [!] Riskli endpoint erişilebilir: {path}")
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.SECURITY_MISCONFIG,
                            severity=Severity.HIGH,
                            target=url,
                            description=f"Riskli endpoint erişilebilir: {path}",
                            evidence=f"HTTP 200 dönüyor",
                            cwe="CWE-200",
                            remediation=f"{path} endpoint'ini production'da kapatın "
                                        f"veya kimlik doğrulama arkasına alın.",
                            details={"path": path},
                        ))
            except requests.RequestException:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                    self._aborted = True
                    self.log(f"Üst üste hata, tarama durduruluyor", "warning")
                    break
                continue
        return vulns

    def _check_directory_listing(self, target: str) -> List[Vulnerability]:
        vulns = []
        for path in DIRECTORY_LISTING_PATHS:
            if self._aborted:
                break
            url = target + path
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                self._consecutive_failures = 0
                if response.status_code == 200 and \
                   ("Index of" in response.text or "<title>Index of" in response.text):
                    self.log(f"  [!] Açık dizin listeleme: {path}")
                    vulns.append(Vulnerability(
                        vuln_type=VulnType.SECURITY_MISCONFIG,
                        severity=Severity.MEDIUM,
                        target=url,
                        description=f"Dizin listeleme açık: {path}",
                        evidence="Sayfada 'Index of' başlığı tespit edildi",
                        cwe="CWE-548",
                        remediation="Apache: Options -Indexes. "
                                    "Nginx: autoindex off; kullanın.",
                        details={"path": path},
                    ))
            except requests.RequestException:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                    self._aborted = True
                    break
                continue
        return vulns
