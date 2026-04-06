"""
Siber Savascilar — SQLMap Cikti Ayristirici
==============================================

SQLMap'in konsol ciktilarini ve log dosyalarini ayristirarak
yapilandirilmis Vulnerability ve ScanResult nesnelerine donusturen modul.

SQLMap Cikti Formatlari:
    1. Konsol ciktisi (stdout/stderr) — Regex ile parse edilir
    2. Log dosyasi (target dizini altindaki log dosyasi)
    3. Session dosyasi (SQLite formatinda — ileride desteklenebilir)

Parse Edilen Bilgiler:
    - Injection noktalari (parametre, teknik, payload)
    - Veritabani tipi ve versiyonu
    - Bulunan veritabanlari ve tablolar
    - Risk/Kritiklik seviyesi tespiti
"""

import re
import os
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

from src.models.scan_result import Vulnerability, ScanResult, Severity, ScanStatus


class SQLMapOutputParser:
    """
    SQLMap ciktilarini yapilandirilmis veriye donusturen ayristirici.
    
    Hem konsol ciktisini hem de SQLMap'in output dizinindeki dosyalari
    parse edebilir. Sonuclar Vulnerability nesneleri olarak doner.
    """

    # ─────────────────────────────────────────────────────────────────────
    # Regex Pattern'leri
    # ─────────────────────────────────────────────────────────────────────

    # SQLMap injection tespit satiri
    # Ornek: "Parameter: id (GET)"
    PARAM_PATTERN = re.compile(
        r"Parameter:\s+(?P<param>\S+)\s+\((?P<method>GET|POST|Cookie|Header|URI)\)",
        re.IGNORECASE,
    )

    # Injection tipi ve baslik
    # Ornek: "    Type: boolean-based blind"
    TYPE_PATTERN = re.compile(
        r"^\s+Type:\s+(?P<type>.+)$",
        re.MULTILINE,
    )

    # Injection basligi
    # Ornek: "    Title: AND boolean-based blind - WHERE or HAVING clause"
    TITLE_PATTERN = re.compile(
        r"^\s+Title:\s+(?P<title>.+)$",
        re.MULTILINE,
    )

    # Payload
    # Ornek: "    Payload: id=1 AND 5765=5765"
    PAYLOAD_PATTERN = re.compile(
        r"^\s+Payload:\s+(?P<payload>.+)$",
        re.MULTILINE,
    )

    # DBMS bilgisi
    # Ornek: "back-end DBMS: MySQL >= 5.0"
    # Veya:  "web application technology: PHP 7.4, Apache 2.4"
    DBMS_PATTERN = re.compile(
        r"back-end DBMS:\s+(?P<dbms>.+)",
        re.IGNORECASE,
    )

    # DBMS versiyon detayi
    DBMS_VERSION_PATTERN = re.compile(
        r"back-end DBMS:\s+(?P<dbms>\w[\w\s]*?)\s*(?:>=?\s*(?P<version>[\d.]+))?$",
        re.IGNORECASE,
    )

    # SQLMap versiyon bilgisi
    # Ornek: "{1.8.4#stable}" veya "sqlmap/1.8.4"
    SQLMAP_VERSION_PATTERN = re.compile(
        r"(?:sqlmap/|\{)(?P<version>[\d.]+(?:#\w+)?(?:dev)?)",
        re.IGNORECASE,
    )

    # Veritabani listesi
    # Ornek: "[*] information_schema"
    DATABASE_PATTERN = re.compile(
        r"^\[\*\]\s+(?P<database>\S+)$",
        re.MULTILINE,
    )

    # Tablo listesi
    TABLE_PATTERN = re.compile(
        r"^\|\s+(?P<table>\S+)\s+\|$",
        re.MULTILINE,
    )

    # Tarama tamamlandi mesaji
    SCAN_COMPLETE_PATTERN = re.compile(
        r"sqlmap identified the following injection point",
        re.IGNORECASE,
    )

    # Zafiyet bulunamadi mesaji
    NO_VULN_PATTERN = re.compile(
        r"(?:all tested parameters do not appear to be injectable|"
        r"no parameter\(s\) found for testing)",
        re.IGNORECASE,
    )

    # Hata mesajlari
    ERROR_PATTERNS = [
        re.compile(r"\[CRITICAL\]\s+(?P<error>.+)", re.IGNORECASE),
        re.compile(r"connection timed out", re.IGNORECASE),
        re.compile(r"unable to connect", re.IGNORECASE),
    ]

    # ─────────────────────────────────────────────────────────────────────
    # Teknik → Severity Eslemesi
    # ─────────────────────────────────────────────────────────────────────

    TECHNIQUE_SEVERITY_MAP = {
        "boolean-based blind": Severity.HIGH,
        "error-based": Severity.HIGH,
        "union query-based": Severity.CRITICAL,
        "union query": Severity.CRITICAL,
        "stacked queries": Severity.CRITICAL,
        "time-based blind": Severity.MEDIUM,
        "inline query": Severity.CRITICAL,
        "and/or time-based blind": Severity.MEDIUM,
    }

    # Teknik kisa isim → tam isim eslemesi
    TECHNIQUE_NORMALIZE = {
        "boolean-based blind": "Boolean-based blind",
        "error-based": "Error-based",
        "union query-based": "Union query-based",
        "union query": "Union query-based",
        "stacked queries": "Stacked queries",
        "time-based blind": "Time-based blind",
        "inline query": "Inline query",
        "and/or time-based blind": "Time-based blind",
    }

    # ─────────────────────────────────────────────────────────────────────
    # Ana Parse Metodlari
    # ─────────────────────────────────────────────────────────────────────

    def parse_console_output(self, raw_output: str) -> List[Vulnerability]:
        """
        SQLMap konsol ciktisini parse ederek zafiyet listesi doner.
        
        Args:
            raw_output: SQLMap'in stdout/stderr ciktisi.
            
        Returns:
            Bulunan zafiyetlerin listesi.
        """
        if not raw_output:
            return []

        vulnerabilities = []
        current_param = ""
        current_method = ""
        current_type = ""
        current_title = ""
        current_payload = ""
        dbms = ""
        dbms_version = ""

        # DBMS bilgisini cikar (global)
        dbms, dbms_version = self._extract_dbms_info(raw_output)

        # Injection bloklarini parse et
        lines = raw_output.split("\n")
        in_injection_block = False

        for i, line in enumerate(lines):
            # Parametre satiri — yeni injection blogu
            param_match = self.PARAM_PATTERN.search(line)
            if param_match:
                current_param = param_match.group("param")
                current_method = param_match.group("method")
                in_injection_block = True
                continue

            if not in_injection_block:
                continue

            # Type satiri
            type_match = self.TYPE_PATTERN.match(line)
            if type_match:
                # Onceki injection'i kaydet (eger varsa)
                if current_type and current_title:
                    vuln = self._create_vulnerability(
                        param=current_param,
                        method=current_method,
                        technique=current_type,
                        title=current_title,
                        payload=current_payload,
                        dbms=dbms,
                        dbms_version=dbms_version,
                    )
                    vulnerabilities.append(vuln)

                current_type = type_match.group("type").strip()
                current_title = ""
                current_payload = ""
                continue

            # Title satiri
            title_match = self.TITLE_PATTERN.match(line)
            if title_match:
                current_title = title_match.group("title").strip()
                continue

            # Payload satiri
            payload_match = self.PAYLOAD_PATTERN.match(line)
            if payload_match:
                current_payload = payload_match.group("payload").strip()
                continue

            # Bos satir veya yeni bolum — blogu kapat
            if line.strip() == "---" or (
                line.strip() == "" and current_type and current_title
            ):
                if current_type and current_title:
                    vuln = self._create_vulnerability(
                        param=current_param,
                        method=current_method,
                        technique=current_type,
                        title=current_title,
                        payload=current_payload,
                        dbms=dbms,
                        dbms_version=dbms_version,
                    )
                    vulnerabilities.append(vuln)
                    current_type = ""
                    current_title = ""
                    current_payload = ""

        # Son kaydedilmemis injection
        if current_type and current_title:
            vuln = self._create_vulnerability(
                param=current_param,
                method=current_method,
                technique=current_type,
                title=current_title,
                payload=current_payload,
                dbms=dbms,
                dbms_version=dbms_version,
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def parse_full_output(self, raw_output: str, config_dict: dict = None) -> ScanResult:
        """
        SQLMap ciktisini tam ScanResult nesnesine donusturur.
        
        Args:
            raw_output:   SQLMap konsol ciktisi.
            config_dict:  Kullanilan yapilandirma (opsiyonel).
            
        Returns:
            Tum bilgileri iceren ScanResult nesnesi.
        """
        result = ScanResult()
        result.raw_output = raw_output
        result.scan_config = config_dict or {}

        # SQLMap versiyonu
        version_match = self.SQLMAP_VERSION_PATTERN.search(raw_output)
        if version_match:
            result.sqlmap_version = version_match.group("version")

        # Zafiyetleri parse et
        result.vulnerabilities = self.parse_console_output(raw_output)

        # Durum belirle
        # Once "zafiyet bulunamadi" kontrolu yap — cunku SQLMap bu mesaji
        # [CRITICAL] seviyesiyle yaziyor ama aslinda bir hata degil
        if self.NO_VULN_PATTERN.search(raw_output):
            result.status = ScanStatus.COMPLETED
        elif result.vulnerabilities:
            result.status = ScanStatus.COMPLETED
        elif self._check_errors(raw_output):
            result.status = ScanStatus.ERROR
            result.error_message = self._extract_error_message(raw_output)
        else:
            result.status = ScanStatus.COMPLETED

        # Ozet olustur
        result.generate_summary()

        return result

    def parse_log_file(self, log_path: str) -> List[Vulnerability]:
        """
        SQLMap log dosyasini parse eder.
        
        Args:
            log_path: Log dosyasinin yolu.
            
        Returns:
            Bulunan zafiyetlerin listesi.
            
        Raises:
            FileNotFoundError: Log dosyasi bulunamazsa.
        """
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Log dosyasi bulunamadi: {log_path}")

        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        return self.parse_console_output(content)

    def parse_target_results(self, output_dir: str, target_url: str = "") -> ScanResult:
        """
        SQLMap output dizinindeki tum sonuclari parse eder.
        
        SQLMap, --output-dir ile belirtilen dizine hedef bazli
        alt dizinler olusturur. Bu metod o dizini tarar.
        
        Args:
            output_dir:  SQLMap output dizini.
            target_url:  Hedef URL (ScanResult'a eklemek icin).
            
        Returns:
            Tum bilgileri iceren ScanResult nesnesi.
        """
        result = ScanResult(target_url=target_url)

        if not os.path.isdir(output_dir):
            result.status = ScanStatus.ERROR
            result.error_message = f"Output dizini bulunamadi: {output_dir}"
            return result

        # SQLMap output dizin yapisi: output_dir/hostname/log
        all_vulns = []
        for root, dirs, files in os.walk(output_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                if filename == "log":
                    try:
                        vulns = self.parse_log_file(file_path)
                        all_vulns.extend(vulns)
                    except Exception:
                        pass

        result.vulnerabilities = all_vulns
        result.status = ScanStatus.COMPLETED
        result.generate_summary()
        return result

    # ─────────────────────────────────────────────────────────────────────
    # Yardimci Extraction Metodlari
    # ─────────────────────────────────────────────────────────────────────

    def extract_injection_points(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Ciktidan injection noktalarini ozet olarak cikarir.
        
        Args:
            raw_output: SQLMap konsol ciktisi.
            
        Returns:
            Injection noktasi sozluklerinin listesi.
        """
        vulns = self.parse_console_output(raw_output)
        points = []
        for v in vulns:
            points.append({
                "parameter": v.parameter,
                "injection_type": v.injection_type,
                "technique": v.technique,
                "title": v.title,
                "payload": v.payload,
                "severity": v.severity,
            })
        return points

    def extract_databases(self, raw_output: str) -> List[str]:
        """SQLMap ciktisindan bulunan veritabani isimlerini cikarir."""
        matches = self.DATABASE_PATTERN.findall(raw_output)
        return [m for m in matches if m.lower() not in ("available", "databases")]

    def extract_tables(self, raw_output: str) -> List[str]:
        """SQLMap ciktisindan bulunan tablo isimlerini cikarir."""
        return self.TABLE_PATTERN.findall(raw_output)

    def determine_severity(self, technique: str, dbms: str = "") -> str:
        """
        Injection teknigine ve DBMS'e gore kritiklik seviyesi belirler.
        
        Mantik:
        - Union/Stacked/Inline → CRITICAL (veri sizdirma/komut calistirma)
        - Boolean/Error-based → HIGH (veri sizdirma potansiyeli)
        - Time-based → MEDIUM (daha yavas ve sinirli)
        
        Args:
            technique: Injection teknigi ismi.
            dbms:      Veritabani turu (opsiyonel, bazi DBMS'ler daha riskli).
            
        Returns:
            Severity string'i ("Critical", "High", "Medium", "Low").
        """
        technique_lower = technique.lower().strip()

        # Dogrudan eslesme
        severity = self.TECHNIQUE_SEVERITY_MAP.get(technique_lower)
        if severity:
            return severity

        # Kismi eslesme
        for key, sev in self.TECHNIQUE_SEVERITY_MAP.items():
            if key in technique_lower:
                return sev

        # DBMS bazli ayarlama — stacked queries MSSQL'de daha tehlikeli
        if dbms and "mssql" in dbms.lower():
            if "stacked" in technique_lower:
                return Severity.CRITICAL

        return Severity.MEDIUM  # Varsayilan

    # ─────────────────────────────────────────────────────────────────────
    # Private Yardimcilar
    # ─────────────────────────────────────────────────────────────────────

    def _extract_dbms_info(self, raw_output: str) -> Tuple[str, str]:
        """DBMS adi ve versiyonunu cikarir."""
        version_match = self.DBMS_VERSION_PATTERN.search(raw_output)
        if version_match:
            dbms = version_match.group("dbms").strip()
            version = version_match.group("version") or ""
            return dbms, version

        simple_match = self.DBMS_PATTERN.search(raw_output)
        if simple_match:
            return simple_match.group("dbms").strip(), ""

        return "", ""

    def _create_vulnerability(
        self,
        param: str,
        method: str,
        technique: str,
        title: str,
        payload: str,
        dbms: str,
        dbms_version: str,
    ) -> Vulnerability:
        """Parsed verilerden Vulnerability nesnesi olusturur."""
        # Teknik ismini normalize et
        normalized_technique = self.TECHNIQUE_NORMALIZE.get(
            technique.lower().strip(), technique
        )

        # Severity belirle
        severity = self.determine_severity(technique, dbms)

        return Vulnerability(
            vuln_type="SQLi",
            severity=severity,
            parameter=param,
            technique=normalized_technique,
            injection_type=method,
            payload=payload,
            dbms=dbms,
            dbms_version=dbms_version,
            title=title,
            details={
                "original_technique": technique,
            },
        )

    def _check_errors(self, raw_output: str) -> bool:
        """Ciktida kritik hata var mi kontrol eder."""
        for pattern in self.ERROR_PATTERNS:
            if pattern.search(raw_output):
                return True
        return False

    def _extract_error_message(self, raw_output: str) -> str:
        """Ilk kritik hata mesajini cikarir."""
        for pattern in self.ERROR_PATTERNS:
            match = pattern.search(raw_output)
            if match:
                try:
                    return match.group("error")
                except IndexError:
                    return match.group(0)
        return "Bilinmeyen hata"
