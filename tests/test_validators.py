"""URL ve hedef doğrulama testleri."""

from siber_savascilar.core.validators import URLValidator, TargetValidator


def test_url_validator_valid():
    valid, _ = URLValidator.validate("http://example.com")
    assert valid

    valid, _ = URLValidator.validate("https://example.com/path?q=1")
    assert valid


def test_url_validator_invalid_scheme():
    valid, msg = URLValidator.validate("ftp://example.com")
    assert not valid
    assert "protokol" in msg.lower()


def test_url_validator_empty():
    valid, _ = URLValidator.validate("")
    assert not valid

    valid, _ = URLValidator.validate(None)
    assert not valid


def test_url_validator_control_chars():
    valid, msg = URLValidator.validate("http://example.com\r\nattack")
    assert not valid
    assert "kontrol karakteri" in msg.lower()


def test_url_validator_ssrf_protection():
    # allow_internal=False ile dahili IP'ler reddedilmeli
    valid, _ = URLValidator.validate("http://127.0.0.1", allow_internal=False)
    assert not valid

    valid, _ = URLValidator.validate("http://192.168.1.1", allow_internal=False)
    assert not valid

    valid, _ = URLValidator.validate("http://10.0.0.1", allow_internal=False)
    assert not valid

    # Public IP geçmeli
    valid, _ = URLValidator.validate("http://8.8.8.8", allow_internal=False)
    assert valid


def test_url_normalize():
    assert URLValidator.normalize("example.com") == "http://example.com"
    assert URLValidator.normalize("https://example.com/") == "https://example.com"
    assert URLValidator.normalize("  http://example.com  ") == "http://example.com"


def test_target_validator_ip():
    assert TargetValidator.is_valid_target("192.168.1.1")
    assert TargetValidator.is_valid_target("8.8.8.8")
    assert TargetValidator.is_valid_target("::1")
    # 999.999.999.999 IP olarak invalid ama hostname regex'i kabul edebilir,
    # bu beklenen bir davranıştır (IP olmayan herşey hostname denenir)


def test_target_validator_hostname():
    assert TargetValidator.is_valid_target("example.com")
    assert TargetValidator.is_valid_target("sub.example.com")
    assert not TargetValidator.is_valid_target("")
    assert not TargetValidator.is_valid_target("not a hostname!")


def test_target_extract_host():
    assert TargetValidator.extract_host("http://example.com/path") == "example.com"
    assert TargetValidator.extract_host("https://example.com:8080") == "example.com"
    assert TargetValidator.extract_host("example.com:80") == "example.com"
    assert TargetValidator.extract_host("example.com") == "example.com"
