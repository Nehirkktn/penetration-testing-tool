"""
Validators — Birim Testleri
==============================

URLValidator ve ConfigValidator siniflarinin dogrulama testleri.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.utils.validators import URLValidator, ConfigValidator


# ─────────────────────────────────────────────────────────────────────────────
# URL Dogrulama Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestURLValidator:
    """URL dogrulama testleri."""

    def test_valid_http_url(self):
        is_valid, msg = URLValidator.validate_url("http://example.com/page?id=1")
        assert is_valid

    def test_valid_https_url(self):
        is_valid, msg = URLValidator.validate_url("https://secure.example.com/api")
        assert is_valid

    def test_valid_ip_url(self):
        is_valid, msg = URLValidator.validate_url("http://192.168.1.1:8080/test")
        assert is_valid

    def test_valid_localhost(self):
        is_valid, msg = URLValidator.validate_url("http://localhost:3000/page")
        assert is_valid

    def test_invalid_scheme(self):
        is_valid, msg = URLValidator.validate_url("ftp://example.com")
        assert not is_valid
        assert "Desteklenmeyen protokol" in msg

    def test_no_scheme(self):
        is_valid, msg = URLValidator.validate_url("example.com/page")
        assert not is_valid

    def test_empty_url(self):
        is_valid, msg = URLValidator.validate_url("")
        assert not is_valid

    def test_none_url(self):
        is_valid, msg = URLValidator.validate_url(None)
        assert not is_valid

    def test_invalid_ip(self):
        is_valid, msg = URLValidator.validate_url("http://999.999.999.999")
        assert not is_valid
        assert "Gecersiz IP" in msg

    def test_has_parameters(self):
        assert URLValidator.has_parameters("http://example.com/page?id=1")
        assert not URLValidator.has_parameters("http://example.com/page")

    def test_extract_parameters(self):
        params = URLValidator.extract_parameters(
            "http://example.com/page?id=1&name=test"
        )
        assert "id" in params
        assert "name" in params

    def test_sqli_test_suitability(self):
        """SQL injection testi uygunluk kontrolu."""
        is_ok, msg = URLValidator.validate_for_sqli_test(
            "http://example.com/page?id=1"
        )
        assert is_ok
        assert "parametre" in msg.lower() or "uygun" in msg.lower()

    def test_sqli_test_no_params(self):
        """Parametresiz URL — uyari vermeli ama gecerli olmali."""
        is_ok, msg = URLValidator.validate_for_sqli_test(
            "http://example.com/page"
        )
        assert is_ok
        assert "⚠️" in msg


# ─────────────────────────────────────────────────────────────────────────────
# DBMS Dogrulama Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigValidatorDBMS:
    """DBMS dogrulama testleri."""

    def test_valid_mysql(self):
        is_valid, result = ConfigValidator.validate_dbms("mysql")
        assert is_valid

    def test_valid_postgresql(self):
        is_valid, result = ConfigValidator.validate_dbms("postgresql")
        assert is_valid

    def test_valid_sqlite(self):
        is_valid, result = ConfigValidator.validate_dbms("sqlite")
        assert is_valid

    def test_valid_mssql(self):
        is_valid, result = ConfigValidator.validate_dbms("mssql")
        assert is_valid

    def test_valid_oracle(self):
        is_valid, result = ConfigValidator.validate_dbms("oracle")
        assert is_valid

    def test_alias_postgres(self):
        """'postgres' alias'i 'postgresql' olarak cozulmeli."""
        is_valid, result = ConfigValidator.validate_dbms("postgres")
        assert is_valid
        assert result == "postgresql"

    def test_alias_mariadb(self):
        """'mariadb' alias'i 'mysql' olarak cozulmeli."""
        is_valid, result = ConfigValidator.validate_dbms("mariadb")
        assert is_valid
        assert result == "mysql"

    def test_empty_dbms(self):
        """Bos DBMS — gecerli (otomatik tespit)."""
        is_valid, result = ConfigValidator.validate_dbms("")
        assert is_valid

    def test_invalid_dbms(self):
        """Gecersiz DBMS adi."""
        is_valid, msg = ConfigValidator.validate_dbms("mongodb")
        assert not is_valid

    def test_case_insensitive(self):
        """Buyuk/kucuk harf duyarsiz DBMS kontrolu."""
        is_valid, _ = ConfigValidator.validate_dbms("MySQL")
        assert is_valid


# ─────────────────────────────────────────────────────────────────────────────
# Teknik, Level, Risk Dogrulama Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigValidatorOthers:
    """Diger dogrulama testleri."""

    def test_valid_techniques(self):
        is_valid, msg = ConfigValidator.validate_techniques("BEUST")
        assert is_valid

    def test_single_technique(self):
        is_valid, msg = ConfigValidator.validate_techniques("B")
        assert is_valid

    def test_invalid_technique(self):
        is_valid, msg = ConfigValidator.validate_techniques("X")
        assert not is_valid

    def test_empty_techniques(self):
        is_valid, msg = ConfigValidator.validate_techniques("")
        assert is_valid  # Bos = tum teknikler

    def test_valid_risk_range(self):
        for r in [1, 2, 3]:
            is_valid, msg = ConfigValidator.validate_risk(r)
            assert is_valid

    def test_invalid_risk(self):
        is_valid, msg = ConfigValidator.validate_risk(5)
        assert not is_valid

    def test_valid_level_range(self):
        for l in [1, 2, 3, 4, 5]:
            is_valid, msg = ConfigValidator.validate_level(l)
            assert is_valid

    def test_invalid_level(self):
        is_valid, msg = ConfigValidator.validate_level(10)
        assert not is_valid

    def test_valid_method(self):
        is_valid, result = ConfigValidator.validate_method("POST")
        assert is_valid
        assert result == "POST"

    def test_invalid_method(self):
        is_valid, msg = ConfigValidator.validate_method("HACK")
        assert not is_valid

    def test_sanitize_parameter(self):
        """Tehlikeli karakterlerin temizlenmesi."""
        result = ConfigValidator.sanitize_parameter("id;rm -rf /")
        assert ";" not in result
        assert "rm" in result  # Harf temizlenmemeli

    def test_sanitize_shell_injection(self):
        """Shell injection denemesinin temizlenmesi."""
        result = ConfigValidator.sanitize_parameter("test$(whoami)")
        assert "$" not in result
        assert "(" not in result

    def test_timeout_valid(self):
        is_valid, msg = ConfigValidator.validate_timeout(60)
        assert is_valid

    def test_timeout_too_low(self):
        is_valid, msg = ConfigValidator.validate_timeout(0)
        assert not is_valid

    def test_timeout_too_high(self):
        is_valid, msg = ConfigValidator.validate_timeout(7200)
        assert not is_valid
