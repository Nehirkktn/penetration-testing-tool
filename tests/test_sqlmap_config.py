"""
SQLMap Config — Birim Testleri
================================

SQLMapConfig sinifinin dogrulama, komut satiri donusumu,
serializasyon ve profil fabrika metodlarini test eder.
"""

import pytest
import sys
import os

# Proje kok dizinini Python yoluna ekle
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.config.sqlmap_config import SQLMapConfig, TECHNIQUE_MAP


# ─────────────────────────────────────────────────────────────────────────────
# Temel Olusturma ve Dogrulama Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLMapConfigCreation:
    """Yapilandirma nesnesi olusturma testleri."""

    def test_default_config(self):
        """Varsayilan degerlerle olusturma."""
        config = SQLMapConfig()
        assert config.target_url == ""
        assert config.level == 1
        assert config.risk == 1
        assert config.batch is True
        assert config.random_agent is True
        assert config.threads == 1
        assert config.timeout == 30

    def test_basic_config(self):
        """Temel parametrelerle olusturma."""
        config = SQLMapConfig(
            target_url="http://example.com/page?id=1",
            dbms="mysql",
            level=3,
            risk=2,
        )
        assert config.target_url == "http://example.com/page?id=1"
        assert config.dbms == "mysql"
        assert config.level == 3
        assert config.risk == 2


class TestSQLMapConfigValidation:
    """Yapilandirma dogrulama testleri."""

    def test_valid_config(self):
        """Gecerli yapilandirma — hata olmamali."""
        config = SQLMapConfig(
            target_url="http://example.com/page?id=1",
            level=3,
            risk=2,
        )
        errors = config.validate()
        assert len(errors) == 0
        assert config.is_valid()

    def test_empty_url(self):
        """Bos URL — hata vermeli."""
        config = SQLMapConfig(target_url="")
        errors = config.validate()
        assert len(errors) > 0
        assert any("target_url" in e for e in errors)

    def test_invalid_url_scheme(self):
        """Gecersiz URL protokolu."""
        config = SQLMapConfig(target_url="ftp://example.com")
        errors = config.validate()
        assert len(errors) > 0

    def test_invalid_level(self):
        """Gecersiz test seviyesi."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            level=10,
        )
        errors = config.validate()
        assert len(errors) > 0
        assert any("Level" in e for e in errors)

    def test_invalid_risk(self):
        """Gecersiz risk seviyesi."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            risk=5,
        )
        errors = config.validate()
        assert len(errors) > 0
        assert any("Risk" in e for e in errors)

    def test_invalid_techniques(self):
        """Gecersiz teknik karakterleri."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            techniques="XYZ",
        )
        errors = config.validate()
        assert len(errors) > 0

    def test_invalid_threads(self):
        """Gecersiz thread sayisi."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            threads=20,
        )
        errors = config.validate()
        assert len(errors) > 0

    def test_valid_techniques(self):
        """Gecerli teknik karakterleri."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            techniques="BEUST",
        )
        assert config.is_valid()


# ─────────────────────────────────────────────────────────────────────────────
# Komut Satiri Donusum Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLMapConfigCommandLine:
    """Komut satiri arguman donusum testleri."""

    def test_basic_command(self):
        """Temel komut olusturma."""
        config = SQLMapConfig(
            target_url="http://example.com/page?id=1",
        )
        args = config.to_command_args()
        assert "-u" in args
        assert "http://example.com/page?id=1" in args
        assert "--batch" in args
        assert "--random-agent" in args

    def test_dbms_in_command(self):
        """DBMS parametresi komutta olmali."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            dbms="mysql",
        )
        args = config.to_command_args()
        assert "--dbms" in args

    def test_level_risk_in_command(self):
        """Level ve risk parametreleri komutta olmali."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            level=5,
            risk=3,
        )
        args = config.to_command_args()
        assert "--level" in args
        assert "5" in args
        assert "--risk" in args
        assert "3" in args

    def test_default_level_risk_not_in_command(self):
        """Varsayilan level/risk (1) komutta olmamali."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
        )
        args = config.to_command_args()
        assert "--level" not in args
        assert "--risk" not in args

    def test_post_data_in_command(self):
        """POST verisi komutta olmali."""
        config = SQLMapConfig(
            target_url="http://example.com/login",
            data="username=admin&password=test",
            method="POST",
        )
        args = config.to_command_args()
        assert "--data" in args
        assert "--method" in args

    def test_techniques_in_command(self):
        """Teknikler komutta olmali."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            techniques="BEU",
        )
        args = config.to_command_args()
        assert "--technique" in args
        assert "BEU" in args

    def test_tamper_in_command(self):
        """Tamper script'leri komutta olmali."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            tamper=["space2comment", "randomcase"],
        )
        args = config.to_command_args()
        assert "--tamper" in args
        assert "space2comment,randomcase" in args

    def test_forms_flag(self):
        """Forms flag'i komutta olmali."""
        config = SQLMapConfig(
            target_url="http://example.com",
            forms=True,
        )
        args = config.to_command_args()
        assert "--forms" in args

    def test_invalid_config_raises(self):
        """Gecersiz yapilandirma ile komut olusturma hata vermeli."""
        config = SQLMapConfig(target_url="")
        with pytest.raises(ValueError):
            config.to_command_args()

    def test_command_string(self):
        """Tam komut string'i olusturma."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
        )
        cmd = config.to_command_string()
        assert cmd.startswith("sqlmap")
        assert "example.com" in cmd

    def test_parameter_in_command(self):
        """Belirli parametre argumani."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1&name=test",
            parameter="id",
        )
        args = config.to_command_args()
        assert "-p" in args
        assert "id" in args

    def test_cookie_in_command(self):
        """Cookie basligi komutta olmali."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            cookie="PHPSESSID=abc123",
        )
        args = config.to_command_args()
        assert "--cookie" in args

    def test_proxy_in_command(self):
        """Proxy parametresi."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            proxy="http://127.0.0.1:8080",
        )
        args = config.to_command_args()
        assert "--proxy" in args

    def test_crawl_depth(self):
        """Crawl derinligi parametresi."""
        config = SQLMapConfig(
            target_url="http://example.com",
            crawl_depth=3,
        )
        args = config.to_command_args()
        assert "--crawl" in args
        assert "3" in args


# ─────────────────────────────────────────────────────────────────────────────
# Serializasyon Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLMapConfigSerialization:
    """Serializasyon ve deserializasyon testleri."""

    def test_to_dict(self):
        """Sozluge donusturme."""
        config = SQLMapConfig(
            target_url="http://example.com?id=1",
            dbms="mysql",
            level=3,
        )
        d = config.to_dict()
        assert isinstance(d, dict)
        assert d["target_url"] == "http://example.com?id=1"
        assert d["dbms"] == "mysql"
        assert d["level"] == 3

    def test_from_dict(self):
        """Sozlukten olusturma."""
        data = {
            "target_url": "http://example.com?id=1",
            "dbms": "postgresql",
            "level": 5,
            "risk": 3,
        }
        config = SQLMapConfig.from_dict(data)
        assert config.target_url == "http://example.com?id=1"
        assert config.dbms == "postgresql"
        assert config.level == 5

    def test_from_dict_extra_fields(self):
        """Tanimsiz alanlarla sozlukten olusturma — hata vermemeli."""
        data = {
            "target_url": "http://example.com?id=1",
            "unknown_field": "should_be_ignored",
        }
        config = SQLMapConfig.from_dict(data)
        assert config.target_url == "http://example.com?id=1"

    def test_roundtrip(self):
        """to_dict → from_dict roundtrip."""
        original = SQLMapConfig(
            target_url="http://test.com?x=1",
            dbms="sqlite",
            level=4,
            risk=2,
            techniques="BET",
            threads=5,
        )
        restored = SQLMapConfig.from_dict(original.to_dict())
        assert restored.target_url == original.target_url
        assert restored.dbms == original.dbms
        assert restored.level == original.level
        assert restored.techniques == original.techniques

    def test_copy(self):
        """Derin kopya testi."""
        original = SQLMapConfig(
            target_url="http://test.com?id=1",
            tamper=["space2comment"],
        )
        copied = original.copy()
        copied.tamper.append("randomcase")
        assert len(original.tamper) == 1  # Orijinal degismemeli


# ─────────────────────────────────────────────────────────────────────────────
# Profil Factory Testleri
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLMapConfigProfiles:
    """Hazir profil factory method testleri."""

    def test_quick_scan(self):
        """Hizli tarama profili."""
        config = SQLMapConfig.quick_scan("http://example.com?id=1")
        assert config.is_valid()
        assert config.level == 1
        assert config.risk == 1
        assert config.techniques == "BE"
        assert config.threads == 4

    def test_standard_scan(self):
        """Standart tarama profili."""
        config = SQLMapConfig.standard_scan("http://example.com?id=1", dbms="mysql")
        assert config.is_valid()
        assert config.level == 3
        assert config.risk == 2
        assert config.dbms == "mysql"

    def test_deep_scan(self):
        """Derin tarama profili."""
        config = SQLMapConfig.deep_scan("http://example.com?id=1")
        assert config.is_valid()
        assert config.level == 5
        assert config.risk == 3
        assert config.forms is True
        assert config.crawl_depth > 0

    def test_post_scan(self):
        """POST tarama profili."""
        config = SQLMapConfig.post_scan(
            "http://example.com/login",
            post_data="user=admin&pass=test",
        )
        assert config.is_valid()
        assert config.data == "user=admin&pass=test"
        assert config.method == "POST"

    def test_quick_scan_with_dbms(self):
        """DBMS belirtilmis hizli tarama."""
        config = SQLMapConfig.quick_scan("http://example.com?id=1", dbms="postgresql")
        assert config.dbms == "postgresql"
        assert config.is_valid()
