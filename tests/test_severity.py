"""Severity sınıfı için detaylı testler."""

import pytest
from siber_savascilar.core.models import Severity


class TestSeverityConstants:
    """Severity sabitlerinin tanımlı ve doğru olduğunu doğrula."""

    def test_critical_constant(self):
        assert Severity.CRITICAL == "Critical"

    def test_high_constant(self):
        assert Severity.HIGH == "High"

    def test_medium_constant(self):
        assert Severity.MEDIUM == "Medium"

    def test_low_constant(self):
        assert Severity.LOW == "Low"

    def test_info_constant(self):
        assert Severity.INFO == "Informational"

    def test_all_constants_are_strings(self):
        for v in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                  Severity.LOW, Severity.INFO]:
            assert isinstance(v, str)


class TestSeverityComparison:
    """Severity karşılaştırma fonksiyonu."""

    def test_critical_greater_than_high(self):
        assert Severity.compare(Severity.CRITICAL, Severity.HIGH) > 0

    def test_high_greater_than_medium(self):
        assert Severity.compare(Severity.HIGH, Severity.MEDIUM) > 0

    def test_medium_greater_than_low(self):
        assert Severity.compare(Severity.MEDIUM, Severity.LOW) > 0

    def test_low_greater_than_info(self):
        assert Severity.compare(Severity.LOW, Severity.INFO) > 0

    def test_equal_severities_returns_zero(self):
        assert Severity.compare(Severity.HIGH, Severity.HIGH) == 0
        assert Severity.compare(Severity.CRITICAL, Severity.CRITICAL) == 0

    def test_unknown_severity_treated_as_lowest(self):
        # Bilinmeyen severity -1 olarak değerlendirilir
        result = Severity.compare("Unknown", Severity.INFO)
        assert result < 0

    @pytest.mark.parametrize("higher,lower", [
        (Severity.CRITICAL, Severity.HIGH),
        (Severity.CRITICAL, Severity.MEDIUM),
        (Severity.CRITICAL, Severity.LOW),
        (Severity.CRITICAL, Severity.INFO),
        (Severity.HIGH, Severity.MEDIUM),
        (Severity.HIGH, Severity.LOW),
        (Severity.HIGH, Severity.INFO),
        (Severity.MEDIUM, Severity.LOW),
        (Severity.MEDIUM, Severity.INFO),
        (Severity.LOW, Severity.INFO),
    ])
    def test_parametrized_ordering(self, higher, lower):
        """Tüm severity çiftleri doğru sıralanmalı."""
        assert Severity.compare(higher, lower) > 0
        assert Severity.compare(lower, higher) < 0


class TestSeverityColors:
    """Severity → renk eşlemesi (rapor görselleştirmesi için)."""

    def test_color_returns_hex_string(self):
        color = Severity.color(Severity.CRITICAL)
        assert color.startswith("#")
        assert len(color) == 7  # #RRGGBB

    @pytest.mark.parametrize("severity", [
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
        Severity.LOW, Severity.INFO
    ])
    def test_all_severities_have_colors(self, severity):
        color = Severity.color(severity)
        assert color.startswith("#")
        assert len(color) == 7

    def test_unknown_severity_returns_default(self):
        color = Severity.color("Bilinmeyen")
        assert color.startswith("#")  # Default gri

    def test_critical_is_red_shade(self):
        # Critical kırmızı tonlarında olmalı
        color = Severity.color(Severity.CRITICAL)
        # Hex'i RGB'ye çevir, R değeri yüksek olmalı
        r = int(color[1:3], 16)
        assert r > 150  # Kırmızı baskın

    def test_different_severities_have_different_colors(self):
        colors = {Severity.color(s) for s in
                  [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                   Severity.LOW, Severity.INFO]}
        # 5 farklı severity → 5 farklı renk
        assert len(colors) == 5


class TestSeverityValidation:
    """is_valid metodu."""

    @pytest.mark.parametrize("valid_value", [
        "Critical", "High", "Medium", "Low", "Informational"
    ])
    def test_valid_severities(self, valid_value):
        assert Severity.is_valid(valid_value) is True

    @pytest.mark.parametrize("invalid_value", [
        "", "critical", "HIGH", "Kritik", "Çok-Yüksek", "Ortabbb",
        "None", "info", "Info", "low",
    ])
    def test_invalid_severities(self, invalid_value):
        assert Severity.is_valid(invalid_value) is False

    def test_validation_is_case_sensitive(self):
        """Severity büyük/küçük harfe duyarlı olmalı."""
        assert Severity.is_valid("Critical") is True
        assert Severity.is_valid("critical") is False
        assert Severity.is_valid("CRITICAL") is False
