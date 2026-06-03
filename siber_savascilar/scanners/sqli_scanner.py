"""
SQL Injection Tarayıcı
=======================

Nursena Karaduman'ın vuln_scanner.py'sindeki sqli_test fonksiyonundan
geliştirilmiş versiyondur. Payload listesi genişletildi, hata pattern'leri
çeşitlendirildi, time-based testler eklendi.
"""

import re
import time
import requests
from typing import List
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from .base import BaseScanner
from ..core.models import Vulnerability, Severity, VulnType


# SQL hata mesajı pattern'leri — DBMS imzaları
SQL_ERROR_PATTERNS = [
    (re.compile(r"sql syntax.*mysql", re.I), "MySQL"),
    (re.compile(r"warning.*mysql_", re.I), "MySQL"),
    (re.compile(r"valid mysql result", re.I), "MySQL"),
    (re.compile(r"mysqlclient\.", re.I), "MySQL"),
    (re.compile(r"postgresql.*error", re.I), "PostgreSQL"),
    (re.compile(r"unterminated quoted string", re.I), "PostgreSQL"),
    (re.compile(r"pg_query\(\)", re.I), "PostgreSQL"),
    (re.compile(r"microsoft sql server", re.I), "MSSQL"),
    (re.compile(r"odbc.*sql server", re.I), "MSSQL"),
    (re.compile(r"unclosed quotation mark", re.I), "MSSQL"),
    (re.compile(r"ora-\d{5}", re.I), "Oracle"),
    (re.compile(r"oracle error", re.I), "Oracle"),
    (re.compile(r"sqlite.*error", re.I), "SQLite"),
    (re.compile(r"sqlite_step", re.I), "SQLite"),
    (re.compile(r"you have an error in your sql", re.I), "Generic SQL"),
    (re.compile(r"sql syntax error", re.I), "Generic SQL"),
]


# Error-based payloadlar
ERROR_PAYLOADS = [
    "'",
    "\"",
    "'--",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1' OR '1'='1' --",
    "') OR ('1'='1",
    "1; SELECT pg_sleep(0)--",
    "' AND 1=CONVERT(int, (SELECT @@version))--",
]

# Time-based blind payloadlar (DBMS'e göre)
TIME_BASED_PAYLOADS = [
    ("' AND SLEEP(5)--", "MySQL", 5),
    ("'; WAITFOR DELAY '0:0:5'--", "MSSQL", 5),
    ("' AND pg_sleep(5)--", "PostgreSQL", 5),
]


class SQLiScanner(BaseScanner):
    """Hata tabanlı + zaman tabanlı SQL Injection tespiti."""

    name = "sqli_scanner"
    description = "Error-based ve time-based SQL Injection tespit"

    # Üst üste bu kadar bağlantı hatası alınırsa erken çık
    MAX_CONSECUTIVE_FAILURES = 3

    def __init__(self, timeout: int = 5, test_time_based: bool = False,
                 verbose: bool = True):
        super().__init__(timeout=timeout, verbose=verbose)
        # Time-based testler yavaş olduğu için varsayılan kapalı
        self.test_time_based = test_time_based
        self._consecutive_failures = 0
        self._aborted = False

    def scan(self, target: str) -> List[Vulnerability]:
        """
        URL'yi SQL injection için test eder.

        URL'de query parameter varsa onları test eder, yoksa yaygın parametre
        adlarıyla (id, q, search, page) deneme yapar.
        """
        self.log(f"SQLi taraması başlıyor: {target}")
        vulns = []

        # URL'deki mevcut parametreleri ayrıştır
        parsed = urlparse(target)
        existing_params = dict(parse_qsl(parsed.query))

        # Yoksa yaygın parametre adlarıyla dene
        if not existing_params:
            existing_params = {"id": "1", "q": "test"}

        for param_name, original_value in existing_params.items():
            if self._aborted:
                self.log("Çok fazla bağlantı hatası, tarama erken sonlandırıldı", "warning")
                break

            self.log(f"  Parametre test ediliyor: {param_name}")

            # Error-based test
            for payload in ERROR_PAYLOADS:
                if self._aborted:
                    break
                test_url = self._build_url(parsed, existing_params, param_name, payload)
                vuln = self._test_error_based(test_url, param_name, payload, target)
                if vuln:
                    vulns.append(vuln)
                    break  # Bir payload için yeterli

            # Time-based test (opsiyonel)
            if self.test_time_based:
                for payload, dbms, expected_delay in TIME_BASED_PAYLOADS:
                    test_url = self._build_url(parsed, existing_params,
                                               param_name, payload)
                    vuln = self._test_time_based(test_url, param_name, payload,
                                                 target, dbms, expected_delay)
                    if vuln:
                        vulns.append(vuln)
                        break

        return vulns

    def _build_url(self, parsed, params, inject_param, payload) -> str:
        """Belirtilen parametreye payload enjekte ederek URL'yi yeniden kurar."""
        new_params = dict(params)
        new_params[inject_param] = payload
        new_query = urlencode(new_params)
        return urlunparse(parsed._replace(query=new_query))

    def _test_error_based(self, url: str, param: str, payload: str,
                          target: str) -> Vulnerability:
        try:
            response = requests.get(url, timeout=self.timeout, verify=False)
            self._consecutive_failures = 0  # Başarılı istek → sayacı sıfırla
            for pattern, dbms in SQL_ERROR_PATTERNS:
                if pattern.search(response.text):
                    self.log(f"    [!] SQL hata pattern'i tespit edildi: {dbms}")
                    return Vulnerability(
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        target=target,
                        parameter=param,
                        payload=payload,
                        description=f"{param} parametresi error-based SQL injection'a açık.",
                        evidence=f"DBMS imzası: {dbms}",
                        cwe="CWE-89",
                        remediation="Parametreli sorgular (prepared statements) kullanın. "
                                    "Kullanıcı girdisini doğrulayın ve escape edin.",
                        details={"dbms": dbms, "url": url},
                    )
        except requests.RequestException as e:
            self._consecutive_failures += 1
            self.log(f"    Bağlantı hatası: {e}", "warning")
            if self._consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
                self._aborted = True
                self.log(f"Üst üste {self.MAX_CONSECUTIVE_FAILURES} hata, "
                         f"hedef ulaşılamaz görünüyor — tarama durduruluyor", "error")
        return None

    def _test_time_based(self, url: str, param: str, payload: str,
                         target: str, dbms: str, expected: int) -> Vulnerability:
        try:
            start = time.time()
            requests.get(url, timeout=self.timeout + expected, verify=False)
            elapsed = time.time() - start

            # Beklenen gecikme yakınsa, blind SQLi var
            if elapsed >= expected - 1:
                self.log(f"    [!] Time-based SQLi: {elapsed:.1f}sn gecikme (DBMS: {dbms})")
                return Vulnerability(
                    vuln_type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    target=target,
                    parameter=param,
                    payload=payload,
                    description=f"{param} parametresi time-based blind SQL injection'a açık.",
                    evidence=f"Gecikme: {elapsed:.1f}sn (beklenen: {expected}sn)",
                    cwe="CWE-89",
                    remediation="Parametreli sorgular kullanın.",
                    details={"dbms": dbms, "delay_seconds": elapsed},
                )
        except requests.RequestException:
            pass
        return None
