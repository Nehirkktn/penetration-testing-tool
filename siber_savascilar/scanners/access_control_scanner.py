"""
Broken Access Control Tarayıcı (OWASP A01:2021)
==================================================

Nursena Karaduman'ın access_control_scanner.py'sinden adapte edilmiştir.

Yönetici paneli erişim ve IDOR testleri yapar.
"""

import requests
from typing import List

from .base import BaseScanner
from ..core.models import Vulnerability, Severity, VulnType


# Yönetici/hassas yollar
ADMIN_PATHS = [
    "/admin", "/admin/dashboard", "/admin/users", "/administrator",
    "/panel", "/yonetim", "/manager", "/superuser",
    "/wp-admin", "/phpmyadmin", "/cpanel",
]

# IDOR testleri
IDOR_PATHS = [
    "/user?id=1", "/user?id=2",
    "/account?id=1", "/profile?user=admin",
    "/api/users/1", "/api/users/2",
    "/api/orders/1",
]

# IDOR cevabında bulunabilecek hassas alanlar
SENSITIVE_FIELDS = ["email", "password", "phone", "address", "token",
                    "ssn", "tckn", "credit_card"]


class AccessControlScanner(BaseScanner):
    """Bozuk erişim kontrolü tarayıcısı."""

    name = "access_control_scanner"
    description = "OWASP A01: Broken Access Control tespit"

    MAX_CONSECUTIVE_FAILURES = 4

    def __init__(self, timeout: int = 5, verbose: bool = True):
        super().__init__(timeout=timeout, verbose=verbose)
        self._consecutive_failures = 0
        self._aborted = False

    def scan(self, target: str) -> List[Vulnerability]:
        self.log(f"Access Control taraması başlıyor: {target}")
        vulns = []

        target = target.rstrip("/")

        vulns.extend(self._test_admin_access(target))
        if not self._aborted:
            vulns.extend(self._test_idor(target))

        return vulns

    def _test_admin_access(self, target: str) -> List[Vulnerability]:
        vulns = []
        for path in ADMIN_PATHS:
            if self._aborted:
                break
            url = target + path
            try:
                response = requests.get(url, timeout=self.timeout, verify=False,
                                        allow_redirects=False)
                self._consecutive_failures = 0

                if response.status_code == 200:
                    # Login formu mu yoksa direkt panel mi?
                    is_login = any(kw in response.text.lower()
                                   for kw in ["login", "giriş", "username", "password"])

                    if not is_login:
                        # Direkt admin paneli açık — kritik
                        self.log(f"  [!] Korumasız admin paneli: {path}")
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.BROKEN_ACCESS,
                            severity=Severity.CRITICAL,
                            target=url,
                            description=f"Yönetici paneli kimlik doğrulamasız erişilebilir: {path}",
                            evidence="HTTP 200 + login formu yok",
                            cwe="CWE-284",
                            remediation="Yönetici endpoint'lerini kimlik doğrulama ve "
                                        "yetkilendirme arkasına alın. Mümkünse "
                                        "/admin yollarını yeniden adlandırın.",
                            details={"path": path},
                        ))
                    else:
                        self.log(f"  [~] Login korumalı: {path}")

            except requests.RequestException:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                    self._aborted = True
                    self.log(f"Üst üste {self.MAX_CONSECUTIVE_FAILURES} hata, "
                             f"tarama durduruluyor", "warning")
                    break
                continue
        return vulns

    def _test_idor(self, target: str) -> List[Vulnerability]:
        vulns = []
        for path in IDOR_PATHS:
            if self._aborted:
                break
            url = target + path
            try:
                response = requests.get(url, timeout=self.timeout, verify=False)
                self._consecutive_failures = 0

                if response.status_code == 200:
                    # Yanıtta hassas alan var mı?
                    text_lower = response.text.lower()
                    found = [field for field in SENSITIVE_FIELDS
                             if field in text_lower]

                    if found:
                        self.log(f"  [!] Potansiyel IDOR: {path} → {found}")
                        vulns.append(Vulnerability(
                            vuln_type=VulnType.IDOR,
                            severity=Severity.HIGH,
                            target=url,
                            description=f"Olası IDOR: {path} kimlik doğrulamasız "
                                        f"hassas veri döndürüyor.",
                            evidence=f"Yanıtta tespit edilen hassas alanlar: "
                                     f"{', '.join(found)}",
                            cwe="CWE-639",
                            remediation="Her endpoint'te kullanıcı yetkilendirmesi "
                                        "yapın. Kullanıcı sadece kendi kaynaklarına "
                                        "erişebilmeli.",
                            details={"path": path, "sensitive_fields": found},
                        ))
            except requests.RequestException:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                    self._aborted = True
                    break
                continue
        return vulns
