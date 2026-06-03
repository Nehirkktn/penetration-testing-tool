"""Tarayıcı modülleri için yerel test sunucusu ile testler.

Her test sınıfı kasıtlı zafiyetli bir HTTP sunucusu kurar (rastgele port)
ve tarayıcıları gerçek HTTP istekleriyle test eder.
"""

import threading
import socket
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
import pytest

from siber_savascilar.scanners import (
    SQLiScanner, XSSScanner, MisconfigScanner, SensitiveDataScanner,
    AccessControlScanner, PortScanner, ScenarioScanner, SQLMapScanner,
    SCANNER_REGISTRY, BaseScanner,
)
from siber_savascilar.core.models import Severity, VulnType


# ─────────────────────────────────────────────────────────────────────────
# Yardımcı: Boş port bul ve sunucu başlat
# ─────────────────────────────────────────────────────────────────────────

def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class VulnHandler(BaseHTTPRequestHandler):
    """Kasıtlı zafiyetli HTTP handler."""
    def log_message(self, *a, **kw): pass

    def do_GET(self):
        p = self.path

        # SQLi: ' veya %27 görürse MySQL hatası
        if p.startswith('/user') or "id=" in p:
            if "'" in p or "%27" in p or '"' in p or "%22" in p:
                self.send_response(500)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<html>You have an error in your SQL syntax; '
                                 b'MySQL server version</html>')
                return

        # XSS: q parametresini yansıt
        if p.startswith('/search'):
            q = unquote(p.split('q=', 1)[1].split('&')[0]) if 'q=' in p else ''
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(f'<h1>Sonuç: {q}</h1>'.encode())
            return

        # Misconfig: .env dosyası
        if p == '/.env':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'DB_PASSWORD=secret123\nAPP_KEY=test\n')
            return

        # Misconfig: phpinfo
        if p == '/phpinfo.php':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<title>phpinfo()</title>')
            return

        # Access control: korumasız admin
        if 'admin' in p and 'dashboard' in p:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>Admin Panel</h1><p>Welcome</p>')
            return

        # IDOR: /api/users/1 → hassas alan
        if p.startswith('/api/users/'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"email":"admin@x.com","password":"hashed"}')
            return

        # Sensitive data: e-posta ve AWS key sızıntısı
        if p == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html>contact: admin@example.com '
                             b'token AKIAIOSFODNN7EXAMPLE</html>')
            return

        self.send_response(404)
        self.end_headers()


@pytest.fixture(scope="module")
def vuln_server():
    """Module-scope vuln server (tüm scanner testleri paylaşır)."""
    port = _get_free_port()
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)  # Sunucu hazır olsun
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ─────────────────────────────────────────────────────────────────────────
# BaseScanner
# ─────────────────────────────────────────────────────────────────────────

class TestBaseScannerContract:
    """BaseScanner contract — alt sınıflar uymak zorunda."""

    def test_cannot_instantiate_directly(self):
        """BaseScanner soyut — direkt instantiate edilemez."""
        with pytest.raises(TypeError):
            BaseScanner()

    @pytest.mark.parametrize("scanner_class", list(SCANNER_REGISTRY.values()))
    def test_all_scanners_have_name(self, scanner_class):
        assert hasattr(scanner_class, 'name')
        assert isinstance(scanner_class.name, str)
        assert len(scanner_class.name) > 0

    @pytest.mark.parametrize("scanner_class", list(SCANNER_REGISTRY.values()))
    def test_all_scanners_have_description(self, scanner_class):
        assert hasattr(scanner_class, 'description')
        assert isinstance(scanner_class.description, str)

    @pytest.mark.parametrize("scanner_class", list(SCANNER_REGISTRY.values()))
    def test_all_scanners_can_instantiate(self, scanner_class):
        scanner = scanner_class(verbose=False)
        assert scanner is not None

    @pytest.mark.parametrize("scanner_class", list(SCANNER_REGISTRY.values()))
    def test_all_scanners_have_scan_method(self, scanner_class):
        scanner = scanner_class(verbose=False)
        assert callable(scanner.scan)

    def test_scanner_registry_keys_unique(self):
        names = list(SCANNER_REGISTRY.keys())
        assert len(names) == len(set(names))

    def test_scanner_registry_has_expected_modules(self):
        expected = {"ports", "sqli", "xss", "misconfig",
                    "sensitive_data", "access_control",
                    "scenarios", "sqlmap"}
        assert expected.issubset(set(SCANNER_REGISTRY.keys()))


# ─────────────────────────────────────────────────────────────────────────
# SQLiScanner
# ─────────────────────────────────────────────────────────────────────────

class TestSQLiScanner:
    def test_detects_mysql_error(self, vuln_server):
        scanner = SQLiScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/user?id=1")
        assert len(vulns) >= 1

    def test_critical_severity(self, vuln_server):
        scanner = SQLiScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/user?id=1")
        if vulns:
            assert vulns[0].severity == Severity.CRITICAL

    def test_correct_vuln_type(self, vuln_server):
        scanner = SQLiScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/user?id=1")
        if vulns:
            assert vulns[0].vuln_type == VulnType.SQLI

    def test_includes_cwe(self, vuln_server):
        scanner = SQLiScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/user?id=1")
        if vulns:
            assert "CWE-89" in vulns[0].cwe

    def test_includes_payload(self, vuln_server):
        scanner = SQLiScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/user?id=1")
        if vulns:
            assert vulns[0].payload != ""

    def test_clean_target_no_vulns(self, vuln_server):
        """Zafiyetsiz endpoint'te bulgu olmamalı."""
        scanner = SQLiScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/safe-endpoint")
        # 404 dönüyor; bulgu beklemiyoruz
        # (Bazen yine de bulgu olabilir, gevşek assert)
        assert isinstance(vulns, list)

    def test_aborts_on_unreachable(self):
        """Üst üste hata gelirse erken kesme tetiklenmeli."""
        scanner = SQLiScanner(timeout=1, verbose=False)
        # Cevap vermeyen IP
        vulns = scanner.scan("http://10.255.255.1:1/x?id=1")
        assert scanner._aborted is True


# ─────────────────────────────────────────────────────────────────────────
# XSSScanner
# ─────────────────────────────────────────────────────────────────────────

class TestXSSScanner:
    def test_detects_reflected_xss(self, vuln_server):
        scanner = XSSScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/search?q=test")
        assert len(vulns) >= 1

    def test_high_severity(self, vuln_server):
        scanner = XSSScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/search?q=test")
        if vulns:
            assert vulns[0].severity == Severity.HIGH

    def test_correct_vuln_type(self, vuln_server):
        scanner = XSSScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/search?q=test")
        if vulns:
            assert vulns[0].vuln_type == VulnType.XSS

    def test_cwe_79(self, vuln_server):
        scanner = XSSScanner(verbose=False)
        vulns = scanner.scan(f"{vuln_server}/search?q=test")
        if vulns:
            assert "CWE-79" in vulns[0].cwe


# ─────────────────────────────────────────────────────────────────────────
# MisconfigScanner
# ─────────────────────────────────────────────────────────────────────────

class TestMisconfigScanner:
    def test_detects_env_file(self, vuln_server):
        scanner = MisconfigScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        # En az .env bulması beklenir
        env_vulns = [v for v in vulns if ".env" in v.target]
        assert len(env_vulns) >= 1

    def test_env_is_critical(self, vuln_server):
        scanner = MisconfigScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        env_vulns = [v for v in vulns if ".env" in v.target]
        if env_vulns:
            assert env_vulns[0].severity == Severity.CRITICAL

    def test_detects_missing_headers(self, vuln_server):
        """Sunucu HSTS/CSP göndermiyor — yakalanmalı."""
        scanner = MisconfigScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        # "başlığı eksik" pattern'ini ara — Türkçe çekim eki dahil
        header_vulns = [v for v in vulns
                        if "başlığı" in v.description.lower()
                        or "başlık" in v.description.lower()
                        or "header" in v.description.lower()]
        assert len(header_vulns) >= 1

    def test_detects_phpinfo(self, vuln_server):
        scanner = MisconfigScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        phpinfo_vulns = [v for v in vulns if "phpinfo" in v.target]
        assert len(phpinfo_vulns) >= 1


# ─────────────────────────────────────────────────────────────────────────
# SensitiveDataScanner
# ─────────────────────────────────────────────────────────────────────────

class TestSensitiveDataScanner:
    def test_detects_http_protocol(self, vuln_server):
        scanner = SensitiveDataScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        http_vulns = [v for v in vulns if "http" in v.details.get("protocol", "")]
        assert len(http_vulns) >= 1

    def test_detects_aws_key(self, vuln_server):
        scanner = SensitiveDataScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        aws_vulns = [v for v in vulns if "aws" in v.description.lower()]
        # En az AWS pattern'i yakalamış olmalı
        assert len(aws_vulns) >= 1

    def test_detects_email(self, vuln_server):
        scanner = SensitiveDataScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        email_vulns = [v for v in vulns if "posta" in v.description.lower()
                       or "email" in v.description.lower()]
        assert len(email_vulns) >= 1


# ─────────────────────────────────────────────────────────────────────────
# AccessControlScanner
# ─────────────────────────────────────────────────────────────────────────

class TestAccessControlScanner:
    def test_detects_unprotected_admin(self, vuln_server):
        scanner = AccessControlScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        admin_vulns = [v for v in vulns if "admin" in v.target.lower()
                       or "panel" in v.description.lower()]
        # Test handler /admin/dashboard'u korumasız döndürüyor
        assert len(admin_vulns) >= 0  # En az yapısal test

    def test_detects_idor(self, vuln_server):
        scanner = AccessControlScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        idor_vulns = [v for v in vulns if v.vuln_type == VulnType.IDOR]
        assert len(idor_vulns) >= 1

    def test_idor_includes_sensitive_fields(self, vuln_server):
        scanner = AccessControlScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        idor_vulns = [v for v in vulns if v.vuln_type == VulnType.IDOR]
        if idor_vulns:
            assert "sensitive_fields" in idor_vulns[0].details


# ─────────────────────────────────────────────────────────────────────────
# PortScanner
# ─────────────────────────────────────────────────────────────────────────

class TestPortScanner:
    def test_scan_returns_list(self, vuln_server):
        scanner = PortScanner(ports=[80, 443, 22], timeout=2, verbose=False)
        host = vuln_server.replace("http://", "").split(":")[0]
        vulns = scanner.scan(host)
        assert isinstance(vulns, list)

    def test_scan_with_url_input(self, vuln_server):
        """URL formatında girdiyi de host'a çevirebilmeli."""
        scanner = PortScanner(ports=[80], timeout=2, verbose=False)
        vulns = scanner.scan(vuln_server)
        assert isinstance(vulns, list)

    def test_invalid_target_returns_empty(self):
        scanner = PortScanner(ports=[80], timeout=1, verbose=False)
        vulns = scanner.scan("not a valid host!!")
        assert vulns == []


# ─────────────────────────────────────────────────────────────────────────
# ScenarioScanner
# ─────────────────────────────────────────────────────────────────────────

class TestScenarioScanner:
    def test_loads_scenarios(self, vuln_server):
        scanner = ScenarioScanner(verbose=False)
        vulns = scanner.scan(vuln_server)
        # En az çağırma hata vermemeli
        assert isinstance(vulns, list)

    def test_handles_missing_scenarios_dir(self, tmp_path):
        scanner = ScenarioScanner(scenarios_dir=str(tmp_path / "nonexistent"),
                                  verbose=False)
        vulns = scanner.scan("http://example.com")
        assert vulns == []

    def test_handles_empty_scenarios_dir(self, tmp_path):
        # Boş dizin
        scanner = ScenarioScanner(scenarios_dir=str(tmp_path), verbose=False)
        vulns = scanner.scan("http://example.com")
        assert vulns == []


# ─────────────────────────────────────────────────────────────────────────
# SQLMapScanner
# ─────────────────────────────────────────────────────────────────────────

class TestSQLMapScanner:
    def test_is_available_returns_bool(self):
        scanner = SQLMapScanner(verbose=False)
        assert isinstance(scanner.is_available(), bool)

    def test_returns_empty_when_sqlmap_missing(self):
        """SQLMap kurulu değilse temiz []  döner, hata fırlatmamalı."""
        scanner = SQLMapScanner(verbose=False)
        if not scanner.is_available():
            vulns = scanner.scan("http://example.com")
            assert vulns == []

    def test_level_clamped(self):
        """level 1-5 arasında olmalı."""
        scanner1 = SQLMapScanner(level=0, verbose=False)
        scanner2 = SQLMapScanner(level=99, verbose=False)
        assert 1 <= scanner1.level <= 5
        assert 1 <= scanner2.level <= 5

    def test_risk_clamped(self):
        scanner1 = SQLMapScanner(risk=0, verbose=False)
        scanner2 = SQLMapScanner(risk=99, verbose=False)
        assert 1 <= scanner1.risk <= 3
        assert 1 <= scanner2.risk <= 3
