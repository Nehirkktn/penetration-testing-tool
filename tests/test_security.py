"""
Guvenlik Acigi Regresyon Testleri (Hafta 6)
=============================================

Bu test dosyasi, Hafta 6 kapsaminda giderilen guvenlik aciklarinin
tekrar acilmadigini dogrular. Her test belirli bir CWE/zafiyet
sinifina karsilik gelir.

Kapsanan zafiyetler:
    1. CWE-918: SSRF — Dahili/ozel IP'ye karsi koruma
    2. CWE-93:  CRLF Injection — Header/Cookie/Data
    3. CWE-22:  Path Traversal — output_dir
    4. CWE-88:  Argument Injection — custom_args
    5. CWE-770: Resource Exhaustion — MAX_ACTIVE_SCANS
    6. CWE-532: Sensitive Info in Logs — Komut maskeleme
    7. CWE-78:  Shell Injection — sanitize_parameter (whitelist)
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.utils.validators import URLValidator, ConfigValidator
from src.config.sqlmap_config import SQLMapConfig
from src.scanners.sqlmap_scanner import SQLMapScanner, SQLMapScanError


# ─────────────────────────────────────────────────────────────────────────
# CWE-918: SSRF — Server-Side Request Forgery
# ─────────────────────────────────────────────────────────────────────────

class TestSSRFProtection:
    """SSRF koruma testleri — dahili IP araliklari engellenmelidir."""

    def test_loopback_ipv4_blocked(self):
        is_safe, msg = URLValidator.validate_safe_target("http://127.0.0.1/page?id=1")
        assert not is_safe
        assert "dahili" in msg.lower() or "guvenlik" in msg.lower()

    def test_loopback_ipv4_alt_form_blocked(self):
        # 127.0.0.1 disindaki diger loopback adresleri
        is_safe, _ = URLValidator.validate_safe_target("http://127.10.0.1/test")
        assert not is_safe

    def test_private_192_blocked(self):
        is_safe, _ = URLValidator.validate_safe_target("http://192.168.1.1/admin")
        assert not is_safe

    def test_private_10_blocked(self):
        is_safe, _ = URLValidator.validate_safe_target("http://10.0.0.5/internal")
        assert not is_safe

    def test_private_172_blocked(self):
        is_safe, _ = URLValidator.validate_safe_target("http://172.16.0.1/intranet")
        assert not is_safe

    def test_aws_metadata_blocked(self):
        # Cloud metadata sizdirma — kritik tehdit
        is_safe, msg = URLValidator.validate_safe_target(
            "http://169.254.169.254/latest/meta-data/"
        )
        assert not is_safe

    def test_localhost_hostname_blocked(self):
        is_safe, _ = URLValidator.validate_safe_target("http://localhost/page")
        assert not is_safe

    def test_gcp_metadata_blocked(self):
        is_safe, _ = URLValidator.validate_safe_target(
            "http://metadata.google.internal/"
        )
        assert not is_safe

    def test_zero_address_blocked(self):
        is_safe, _ = URLValidator.validate_safe_target("http://0.0.0.0/test")
        assert not is_safe

    def test_public_ip_allowed(self):
        # Public IP'ler kabul edilmeli
        is_safe, _ = URLValidator.validate_safe_target("http://8.8.8.8/page")
        assert is_safe

    def test_public_domain_allowed(self):
        is_safe, _ = URLValidator.validate_safe_target(
            "http://example.com/page?id=1"
        )
        assert is_safe

    def test_explicit_internal_opt_in(self):
        # Yerel test ortami — acikca izin verildiginde kabul edilmeli
        is_safe, _ = URLValidator.validate_safe_target(
            "http://127.0.0.1/", allow_internal=True
        )
        assert is_safe

    def test_config_blocks_internal_by_default(self):
        config = SQLMapConfig(target_url="http://127.0.0.1/page?id=1")
        errors = config.validate()
        assert any("dahili" in e.lower() or "guvenlik" in e.lower() for e in errors)

    def test_config_allows_internal_when_flag_set(self):
        config = SQLMapConfig(
            target_url="http://127.0.0.1/page?id=1",
            allow_internal_targets=True,
        )
        errors = config.validate()
        # Hicbir hata olmamali (yerel test acikca izin verildi)
        assert errors == []


# ─────────────────────────────────────────────────────────────────────────
# CWE-93: CRLF Injection — HTTP Response Splitting / Header Injection
# ─────────────────────────────────────────────────────────────────────────

class TestCRLFInjectionProtection:
    """Header, Cookie ve POST data alanlarinda CRLF injection korumasi."""

    def test_header_with_crlf_blocked(self):
        is_valid, _ = ConfigValidator.validate_header(
            "X-Custom", "value\r\nInjected: yes"
        )
        assert not is_valid

    def test_header_with_lf_blocked(self):
        is_valid, _ = ConfigValidator.validate_header("X-Custom", "value\nx")
        assert not is_valid

    def test_header_with_cr_blocked(self):
        is_valid, _ = ConfigValidator.validate_header("X-Custom", "value\rx")
        assert not is_valid

    def test_header_with_null_blocked(self):
        is_valid, _ = ConfigValidator.validate_header("X-Custom", "value\x00x")
        assert not is_valid

    def test_invalid_header_name_blocked(self):
        # Bosluklu header adi RFC 7230 ihlali
        is_valid, _ = ConfigValidator.validate_header(
            "Bad Header Name", "ok"
        )
        assert not is_valid

    def test_valid_header_accepted(self):
        is_valid, _ = ConfigValidator.validate_header(
            "X-API-Key", "abc123token"
        )
        assert is_valid

    def test_cookie_with_crlf_blocked(self):
        is_valid, _ = ConfigValidator.validate_cookie(
            "PHPSESSID=abc\r\nSet-Cookie: evil=1"
        )
        assert not is_valid

    def test_cookie_valid(self):
        is_valid, _ = ConfigValidator.validate_cookie("PHPSESSID=abcdef123")
        assert is_valid

    def test_data_with_crlf_blocked(self):
        is_valid, _ = ConfigValidator.validate_data(
            "user=admin&pass=secret\r\nGET /admin HTTP/1.1"
        )
        assert not is_valid

    def test_data_valid(self):
        is_valid, _ = ConfigValidator.validate_data(
            "username=admin&password=test"
        )
        assert is_valid

    def test_url_with_crlf_blocked(self):
        is_valid, _ = URLValidator.validate_url(
            "http://example.com/page\r\nHost: evil.com"
        )
        assert not is_valid

    def test_config_rejects_malicious_header(self):
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            headers={"X-Test": "ok\r\nX-Evil: 1"},
        )
        errors = config.validate()
        assert any("Header" in e for e in errors)


# ─────────────────────────────────────────────────────────────────────────
# CWE-22: Path Traversal — output_dir
# ─────────────────────────────────────────────────────────────────────────

class TestPathTraversalProtection:
    """SQLMap output dizininde path traversal saldirilarinin engellenmesi."""

    def test_dotdot_path_rejected(self):
        is_valid, _ = ConfigValidator.validate_output_dir("../../etc/passwd")
        assert not is_valid

    def test_relative_dotdot_path_rejected(self):
        is_valid, _ = ConfigValidator.validate_output_dir(
            "results/../../../tmp"
        )
        assert not is_valid

    def test_etc_directory_rejected(self):
        is_valid, _ = ConfigValidator.validate_output_dir("/etc/sqlmap_out")
        assert not is_valid

    def test_root_directory_rejected(self):
        is_valid, _ = ConfigValidator.validate_output_dir("/root/results")
        assert not is_valid

    def test_proc_directory_rejected(self):
        is_valid, _ = ConfigValidator.validate_output_dir("/proc/self/data")
        assert not is_valid

    def test_null_byte_rejected(self):
        is_valid, _ = ConfigValidator.validate_output_dir(
            "/tmp/safe\x00/etc/passwd"
        )
        assert not is_valid

    def test_safe_tmp_path_accepted(self):
        is_valid, _ = ConfigValidator.validate_output_dir("/tmp/sqlmap_out")
        assert is_valid

    def test_relative_safe_path_accepted(self):
        is_valid, _ = ConfigValidator.validate_output_dir("results/scan_001")
        assert is_valid

    def test_config_rejects_traversal(self):
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            output_dir="../../../etc",
        )
        errors = config.validate()
        assert any("Output dizini" in e for e in errors)


# ─────────────────────────────────────────────────────────────────────────
# CWE-88: Argument Injection — custom_args
# ─────────────────────────────────────────────────────────────────────────

class TestArgumentInjectionProtection:
    """Tehlikeli SQLMap bayraklarinin engellenmesi."""

    def test_eval_blocked(self):
        is_valid, _ = ConfigValidator.validate_custom_args([
            "--eval=__import__('os').system('id')"
        ])
        assert not is_valid

    def test_os_cmd_blocked(self):
        is_valid, _ = ConfigValidator.validate_custom_args(["--os-cmd=whoami"])
        assert not is_valid

    def test_os_shell_blocked(self):
        is_valid, _ = ConfigValidator.validate_custom_args(["--os-shell"])
        assert not is_valid

    def test_file_read_blocked(self):
        is_valid, _ = ConfigValidator.validate_custom_args([
            "--file-read", "/etc/passwd"
        ])
        assert not is_valid

    def test_file_write_blocked(self):
        is_valid, _ = ConfigValidator.validate_custom_args([
            "--file-write=/tmp/payload"
        ])
        assert not is_valid

    def test_load_cookies_blocked(self):
        is_valid, _ = ConfigValidator.validate_custom_args([
            "--load-cookies=/etc/passwd"
        ])
        assert not is_valid

    def test_purge_blocked(self):
        is_valid, _ = ConfigValidator.validate_custom_args(["--purge"])
        assert not is_valid

    def test_safe_args_accepted(self):
        is_valid, _ = ConfigValidator.validate_custom_args([
            "--keep-alive", "--skip-urlencode"
        ])
        assert is_valid

    def test_crlf_in_arg_blocked(self):
        is_valid, _ = ConfigValidator.validate_custom_args(["--user-agent=foo\r\nx"])
        assert not is_valid

    def test_config_rejects_dangerous_arg(self):
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            custom_args=["--os-cmd=id"],
        )
        errors = config.validate()
        assert any("os-cmd" in e or "yasaktir" in e for e in errors)


# ─────────────────────────────────────────────────────────────────────────
# CWE-770: Resource Exhaustion — Asenkron tarama limiti
# ─────────────────────────────────────────────────────────────────────────

class TestResourceExhaustionProtection:
    """MAX_ACTIVE_SCANS sayisinin uzerinde tarama acilamamali."""

    def test_max_active_scans_constant_exists(self):
        # Kontrolu acikca etkinlestirilmis olmali
        assert hasattr(SQLMapScanner, "MAX_ACTIVE_SCANS")
        assert isinstance(SQLMapScanner.MAX_ACTIVE_SCANS, int)
        assert SQLMapScanner.MAX_ACTIVE_SCANS >= 1
        assert SQLMapScanner.MAX_ACTIVE_SCANS <= 50  # Mantikli ust limit

    def test_scan_limit_raises_when_exceeded(self):
        """Aktif tarama sayisi limite ulastiginda yeni tarama engellenmeli."""
        scanner = SQLMapScanner(sqlmap_path="/bin/true")
        # _active_scans'i taklit et — gercek subprocess acmadan limit testi
        class _FakeProc:
            def poll(self):
                return None  # Hala calisiyor

        for i in range(scanner.MAX_ACTIVE_SCANS):
            scanner._active_scans[f"task_{i}"] = {
                "process": _FakeProc(),
                "config": {},
                "target_url": f"http://example.com/{i}",
                "started_at": None,
                "output_dir": "",
            }

        config = SQLMapConfig(target_url="http://example.com?id=1")
        with pytest.raises(SQLMapScanError) as exc_info:
            scanner.scan_async(config)
        assert "limit" in str(exc_info.value).lower()


# ─────────────────────────────────────────────────────────────────────────
# CWE-532: Sensitive Information in Logs — Komut maskeleme
# ─────────────────────────────────────────────────────────────────────────

class TestSensitiveDataRedaction:
    """Cookie, header, --data gibi hassas alanlar loglarda maskelenmeli."""

    def test_redact_cookie_flag(self):
        cmd = [
            "sqlmap", "-u", "http://example.com",
            "--cookie", "PHPSESSID=secrettoken123",
        ]
        redacted = SQLMapScanner._redact_command(cmd)
        assert "secrettoken123" not in redacted
        assert "REDACTED" in redacted

    def test_redact_data_flag(self):
        cmd = [
            "sqlmap", "-u", "http://example.com",
            "--data", "password=mySecret123",
        ]
        redacted = SQLMapScanner._redact_command(cmd)
        assert "mySecret123" not in redacted
        assert "REDACTED" in redacted

    def test_redact_inline_format(self):
        cmd = ["sqlmap", "--cookie=session=secrettoken"]
        redacted = SQLMapScanner._redact_command(cmd)
        assert "secrettoken" not in redacted

    def test_redact_header_flag(self):
        cmd = [
            "sqlmap", "--header", "Authorization: Bearer s3cretJwtToken",
        ]
        redacted = SQLMapScanner._redact_command(cmd)
        assert "s3cretJwtToken" not in redacted

    def test_non_sensitive_args_preserved(self):
        cmd = ["sqlmap", "-u", "http://example.com?id=1", "--batch", "--level", "3"]
        redacted = SQLMapScanner._redact_command(cmd)
        assert "http://example.com?id=1" in redacted
        assert "--batch" in redacted
        assert "REDACTED" not in redacted


# ─────────────────────────────────────────────────────────────────────────
# CWE-78: Shell Injection — sanitize_parameter (whitelist)
# ─────────────────────────────────────────────────────────────────────────

class TestSanitizationWhitelist:
    """Yeni whitelist tabanli sanitize_parameter testleri."""

    def test_removes_semicolon(self):
        assert ";" not in ConfigValidator.sanitize_parameter("id;rm")

    def test_removes_backtick(self):
        assert "`" not in ConfigValidator.sanitize_parameter("`whoami`")

    def test_removes_single_quote(self):
        # Onceki kara liste yaklasiminda eksikti
        assert "'" not in ConfigValidator.sanitize_parameter("id' OR 1=1--")

    def test_removes_star(self):
        # Onceki kara liste yaklasiminda eksikti
        assert "*" not in ConfigValidator.sanitize_parameter("id*")

    def test_removes_question_mark(self):
        assert "?" not in ConfigValidator.sanitize_parameter("id?x")

    def test_removes_tilde(self):
        assert "~" not in ConfigValidator.sanitize_parameter("~/etc")

    def test_keeps_alphanumeric(self):
        assert ConfigValidator.sanitize_parameter("user_id") == "user_id"

    def test_keeps_comma(self):
        # Cok parametre destegi: "id,name"
        assert ConfigValidator.sanitize_parameter("id,name") == "id,name"

    def test_empty_input(self):
        assert ConfigValidator.sanitize_parameter("") == ""


# ─────────────────────────────────────────────────────────────────────────
# Proxy Dogrulamasi
# ─────────────────────────────────────────────────────────────────────────

class TestProxyValidation:
    """Proxy URL dogrulama testleri."""

    def test_valid_http_proxy(self):
        is_valid, _ = ConfigValidator.validate_proxy("http://127.0.0.1:8080")
        assert is_valid

    def test_valid_socks5_proxy(self):
        is_valid, _ = ConfigValidator.validate_proxy("socks5://127.0.0.1:1080")
        assert is_valid

    def test_invalid_scheme_rejected(self):
        is_valid, _ = ConfigValidator.validate_proxy("ftp://proxy.local:21")
        assert not is_valid

    def test_proxy_with_crlf_rejected(self):
        is_valid, _ = ConfigValidator.validate_proxy(
            "http://proxy.local\r\nX: y"
        )
        assert not is_valid

    def test_proxy_without_host_rejected(self):
        is_valid, _ = ConfigValidator.validate_proxy("http://")
        assert not is_valid


# ─────────────────────────────────────────────────────────────────────────
# Genel Entegrasyon: SQLMapConfig
# ─────────────────────────────────────────────────────────────────────────

class TestConfigSecurityIntegration:
    """SQLMapConfig'in tum guvenlik kontrollerini orkestre etmesi."""

    def test_safe_config_validates(self):
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            cookie="PHPSESSID=abc123",
            data="username=admin&password=test",
            headers={"X-API-Key": "token123"},
            proxy="http://proxy.example.com:8080",
            output_dir="/tmp/sqlmap_out",
            custom_args=["--keep-alive"],
        )
        errors = config.validate()
        assert errors == []

    def test_multi_violation_config_returns_all_errors(self):
        config = SQLMapConfig(
            target_url="http://127.0.0.1?id=1",            # SSRF
            cookie="abc\r\nX: y",                            # CRLF
            output_dir="../../../etc",                       # Path Traversal
            custom_args=["--os-cmd=id"],                     # Argument Injection
        )
        errors = config.validate()
        # En az 4 farkli hata olmali
        assert len(errors) >= 4
