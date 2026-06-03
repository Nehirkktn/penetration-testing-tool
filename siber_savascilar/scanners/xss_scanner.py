"""
XSS (Cross-Site Scripting) Tarayıcı
=====================================

Nursena Karaduman'ın vuln_scanner.py'sindeki xss_test fonksiyonundan
geliştirilmiş versiyondur.

İyileştirmeler:
    - Daha çeşitli payload setleri (HTML, attribute, JS context)
    - URL parametrelerini otomatik tespit
    - HTML encoding ile filtrelenip filtrelenmediği analizi
"""

import requests
from typing import List
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from .base import BaseScanner
from ..core.models import Vulnerability, Severity, VulnType


# Farklı bağlamlara uygun payloadlar
XSS_PAYLOADS = [
    # Klasik script enjeksiyonu
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",  # Case bypass
    # Image-based
    "<img src=x onerror=alert(1)>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    # SVG-based
    "<svg/onload=alert(1)>",
    # Body-based
    "<body onload=alert(1)>",
    # Tag-breaking
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    # JavaScript URI (a href)
    "javascript:alert(1)",
]


class XSSScanner(BaseScanner):
    """Reflected XSS tespit (response içinde payload yansıması)."""

    name = "xss_scanner"
    description = "Reflected XSS payload yansıma testi"

    MAX_CONSECUTIVE_FAILURES = 3

    def __init__(self, timeout: int = 5, verbose: bool = True):
        super().__init__(timeout=timeout, verbose=verbose)
        self._consecutive_failures = 0
        self._aborted = False

    def scan(self, target: str) -> List[Vulnerability]:
        self.log(f"XSS taraması başlıyor: {target}")
        vulns = []

        parsed = urlparse(target)
        existing_params = dict(parse_qsl(parsed.query))

        if not existing_params:
            existing_params = {"q": "test", "search": "test"}

        for param_name in existing_params.keys():
            if self._aborted:
                self.log("Çok fazla bağlantı hatası, tarama erken sonlandırıldı", "warning")
                break
            self.log(f"  Parametre test ediliyor: {param_name}")
            for payload in XSS_PAYLOADS:
                if self._aborted:
                    break
                test_url = self._build_url(parsed, existing_params,
                                           param_name, payload)
                vuln = self._test_payload(test_url, param_name, payload, target)
                if vuln:
                    vulns.append(vuln)
                    break  # Bir payload yetti, sıradakine geç

        return vulns

    def _build_url(self, parsed, params, inject_param, payload) -> str:
        new_params = dict(params)
        new_params[inject_param] = payload
        return urlunparse(parsed._replace(query=urlencode(new_params)))

    def _test_payload(self, url: str, param: str, payload: str,
                      target: str) -> Vulnerability:
        try:
            response = requests.get(url, timeout=self.timeout, verify=False)
            self._consecutive_failures = 0
            # Payload sayfada birebir geçiyor mu?
            if payload in response.text:
                self.log(f"    [!] XSS yansıması tespit edildi: {payload}")
                return Vulnerability(
                    vuln_type=VulnType.XSS,
                    severity=Severity.HIGH,
                    target=target,
                    parameter=param,
                    payload=payload,
                    description=f"{param} parametresi reflected XSS'e açık. "
                                f"Payload sayfada filtrelenmeden yansıtılıyor.",
                    evidence=f"Response içinde geçen payload: {payload[:80]}",
                    cwe="CWE-79",
                    remediation="Tüm kullanıcı girdilerini HTML-encode edin. "
                                "Content-Security-Policy başlığı tanımlayın. "
                                "Mümkünse framework'ün otomatik escape mekanizmasını "
                                "(Jinja2 autoescape, React jsx, vs.) kullanın.",
                    details={"url": url},
                )
        except requests.RequestException as e:
            self._consecutive_failures += 1
            self.log(f"    Bağlantı hatası: {e}", "warning")
            if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                self._aborted = True
                self.log(f"Üst üste {self.MAX_CONSECUTIVE_FAILURES} hata, "
                         f"hedef ulaşılamaz görünüyor — tarama durduruluyor", "error")
        return None
