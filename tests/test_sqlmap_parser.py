"""
SQLMap Parser — Birim Testleri
================================

SQLMapOutputParser sinifinin konsol ciktisi parse, DBMS tespiti,
severity belirleme ve ScanResult donusum testleri.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parsers.sqlmap_parser import SQLMapOutputParser
from src.models.scan_result import Vulnerability, ScanResult, Severity, ScanStatus


# ─────────────────────────────────────────────────────────────────────────────
# Test Verileri (Mock SQLMap Ciktilari)
# ─────────────────────────────────────────────────────────────────────────────

MOCK_SQLMAP_VULNERABLE_OUTPUT = """
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal.

[*] starting @ 14:30:00 /2026-04-05/

[14:30:01] [INFO] testing connection to the target URL
[14:30:02] [INFO] testing if the target URL content is stable
[14:30:03] [INFO] target URL content is stable
[14:30:04] [INFO] testing if GET parameter 'id' is dynamic
[14:30:05] [INFO] GET parameter 'id' appears to be dynamic
[14:30:06] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[14:30:15] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5765=5765

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 7171 FROM(SELECT COUNT(*),CONCAT(0x716a787071,(SELECT (ELT(7171=7171,1))),0x7178787671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 5318 FROM (SELECT(SLEEP(5)))oQkV)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-7181 UNION ALL SELECT NULL,CONCAT(0x716a787071,0x4f6e457a72554d4c4d6e,0x7178787671),NULL-- -
---
[14:30:30] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
[14:30:30] [INFO] fetched data logged to text files under '/tmp/sqlmap/output/example.com'
"""

MOCK_SQLMAP_NO_VULN_OUTPUT = """
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 15:00:00 /2026-04-05/

[15:00:01] [INFO] testing connection to the target URL
[15:00:10] [WARNING] GET parameter 'q' does not seem to be injectable
[15:00:15] [CRITICAL] all tested parameters do not appear to be injectable.
"""

MOCK_SQLMAP_ERROR_OUTPUT = """
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 16:00:00 /2026-04-05/

[16:00:01] [CRITICAL] unable to connect to the target URL
"""

MOCK_SQLMAP_POST_VULN_OUTPUT = """
sqlmap identified the following injection point(s) with a total of 152 HTTP(s) requests:
---
Parameter: username (POST)
    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: username=admin';SELECT SLEEP(5)#&password=test

    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=-1' OR 5765=5765-- -&password=test
---
back-end DBMS: MySQL >= 5.0.12
"""


# ─────────────────────────────────────────────────────────────────────────────
# Konsol Ciktisi Parse Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestParseConsoleOutput:
    """Konsol ciktisi parse testleri."""

    def setup_method(self):
        self.parser = SQLMapOutputParser()

    def test_parse_vulnerable_output(self):
        """Zafiyetli ciktiyi parse et — 4 zafiyet bulmali."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        assert len(vulns) == 4

    def test_vulnerability_types(self):
        """Zafiyet tiplerinin dogru parse edilmesi."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        techniques = [v.technique for v in vulns]
        assert "Boolean-based blind" in techniques
        assert "Error-based" in techniques
        assert "Time-based blind" in techniques
        assert "Union query-based" in techniques

    def test_parameter_name(self):
        """Parametre isminin dogru cikarilmasi."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        for v in vulns:
            assert v.parameter == "id"

    def test_injection_type(self):
        """Injection tipinin (GET/POST) dogru cikarilmasi."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        for v in vulns:
            assert v.injection_type == "GET"

    def test_payload_extraction(self):
        """Payload'larin dogru cikarilmasi."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        payloads = [v.payload for v in vulns]
        assert any("AND 5765=5765" in p for p in payloads)

    def test_vuln_type_is_sqli(self):
        """Tum zafiyetlerin vuln_type'i 'SQLi' olmali."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        for v in vulns:
            assert v.vuln_type == "SQLi"

    def test_dbms_detection(self):
        """DBMS tespitinin dogrulugu."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        for v in vulns:
            assert "MySQL" in v.dbms

    def test_no_vuln_output(self):
        """Zafiyet bulunamayan cikti — bos liste donmeli."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_NO_VULN_OUTPUT)
        assert len(vulns) == 0

    def test_empty_output(self):
        """Bos cikti — bos liste donmeli."""
        vulns = self.parser.parse_console_output("")
        assert len(vulns) == 0

    def test_post_parameter(self):
        """POST parametreli injection parse."""
        vulns = self.parser.parse_console_output(MOCK_SQLMAP_POST_VULN_OUTPUT)
        assert len(vulns) == 2
        for v in vulns:
            assert v.parameter == "username"
            assert v.injection_type == "POST"


# ─────────────────────────────────────────────────────────────────────────────
# Full Output Parse Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestParseFullOutput:
    """ScanResult'a tam donusum testleri."""

    def setup_method(self):
        self.parser = SQLMapOutputParser()

    def test_full_parse_vulnerable(self):
        """Zafiyetli cikti — ScanResult dogru donmeli."""
        result = self.parser.parse_full_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        assert isinstance(result, ScanResult)
        assert result.status == ScanStatus.COMPLETED
        assert result.vulnerability_count == 4
        assert result.is_vulnerable

    def test_full_parse_no_vuln(self):
        """Zafiyet bulunamayan cikti — ScanResult dogru donmeli."""
        result = self.parser.parse_full_output(MOCK_SQLMAP_NO_VULN_OUTPUT)
        assert result.status == ScanStatus.COMPLETED
        assert result.vulnerability_count == 0
        assert not result.is_vulnerable

    def test_full_parse_error(self):
        """Hata ciktisi — ScanResult hata durumunu gostermeli."""
        result = self.parser.parse_full_output(MOCK_SQLMAP_ERROR_OUTPUT)
        assert result.status == ScanStatus.ERROR
        assert result.error_message != ""

    def test_sqlmap_version_extraction(self):
        """SQLMap surum bilgisinin cikarilmasi."""
        result = self.parser.parse_full_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        assert "1.8.4" in result.sqlmap_version

    def test_summary_generation(self):
        """Otomatik ozet olusturma."""
        result = self.parser.parse_full_output(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        result.target_url = "http://example.com/page?id=1"
        from datetime import datetime, timedelta
        result.started_at = datetime.now()
        result.finished_at = datetime.now() + timedelta(seconds=30)
        summary = result.generate_summary()
        assert "SQL injection" in summary
        assert "4" in summary  # 4 zafiyet


# ─────────────────────────────────────────────────────────────────────────────
# Severity Belirleme Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestSeverityDetermination:
    """Teknige gore severity belirleme testleri."""

    def setup_method(self):
        self.parser = SQLMapOutputParser()

    def test_union_is_critical(self):
        """Union query → Critical."""
        sev = self.parser.determine_severity("union query-based")
        assert sev == Severity.CRITICAL

    def test_stacked_is_critical(self):
        """Stacked queries → Critical."""
        sev = self.parser.determine_severity("stacked queries")
        assert sev == Severity.CRITICAL

    def test_boolean_is_high(self):
        """Boolean-based → High."""
        sev = self.parser.determine_severity("boolean-based blind")
        assert sev == Severity.HIGH

    def test_error_is_high(self):
        """Error-based → High."""
        sev = self.parser.determine_severity("error-based")
        assert sev == Severity.HIGH

    def test_time_is_medium(self):
        """Time-based → Medium."""
        sev = self.parser.determine_severity("time-based blind")
        assert sev == Severity.MEDIUM

    def test_unknown_defaults_to_medium(self):
        """Bilinmeyen teknik → Medium (varsayilan)."""
        sev = self.parser.determine_severity("some-unknown-technique")
        assert sev == Severity.MEDIUM


# ─────────────────────────────────────────────────────────────────────────────
# Extraction Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractionMethods:
    """Yardimci extraction metodlari testleri."""

    def setup_method(self):
        self.parser = SQLMapOutputParser()

    def test_extract_injection_points(self):
        """Injection noktasi cikarma."""
        points = self.parser.extract_injection_points(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        assert len(points) == 4
        assert all("parameter" in p for p in points)
        assert all("severity" in p for p in points)

    def test_extract_databases(self):
        """Veritabani listesi cikarma (mock'ta yok — bos donmeli)."""
        dbs = self.parser.extract_databases(MOCK_SQLMAP_VULNERABLE_OUTPUT)
        # Bu ciktida database listesi yok
        assert isinstance(dbs, list)

    def test_extract_databases_with_data(self):
        """Veritabani listesi mock verisi ile."""
        mock_db_output = """
available databases [3]:
[*] information_schema
[*] mysql
[*] test_db
"""
        dbs = self.parser.extract_databases(mock_db_output)
        assert "information_schema" in dbs
        assert "mysql" in dbs
        assert "test_db" in dbs
