"""
Doğrulama Yardımcıları
=======================

Sefa Kozan'ın validators.py modülünün sadeleştirilmiş genel-amaçlı versiyonu.
Tüm tarayıcılarda kullanılır.

Güvenlik korumaları:
    - SSRF: Özel/dahili IP aralıkları opsiyonel olarak engellenir
    - CRLF: Kontrol karakterleri reddedilir
    - Sadece http/https protokolleri kabul edilir
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple


class URLValidator:
    """URL doğrulama ve normalizasyon."""

    SUPPORTED_SCHEMES = ("http", "https")
    CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

    @classmethod
    def validate(cls, url: str, allow_internal: bool = True) -> Tuple[bool, str]:
        """
        URL'yi doğrular.

        Args:
            url: Doğrulanacak URL
            allow_internal: Dahili IP'lere izin verilsin mi (SSRF koruması)

        Returns:
            (is_valid, message). is_valid False ise message hata mesajıdır.
        """
        if not url or not isinstance(url, str):
            return False, "URL boş veya geçersiz tip."

        url = url.strip()

        if cls.CONTROL_CHARS.search(url):
            return False, "URL kontrol karakteri içeriyor."

        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"URL ayrıştırılamadı: {e}"

        if parsed.scheme not in cls.SUPPORTED_SCHEMES:
            return False, f"Desteklenmeyen protokol: {parsed.scheme}. " \
                          f"Sadece http/https kullanın."

        if not parsed.netloc:
            return False, "URL host bilgisi içermiyor."

        if not allow_internal:
            host = parsed.hostname or ""
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    return False, f"Dahili/özel IP'lere tarama yapılamaz: {host}"
            except ValueError:
                pass  # Hostname (IP değil) — devam et

        return True, "OK"

    @classmethod
    def normalize(cls, url: str) -> str:
        """
        URL'yi normalize eder. Protokol yoksa http:// ekler.

        Örnek:
            example.com → http://example.com
            example.com/ → http://example.com

        Desteklenmeyen protokoller olduğu gibi bırakılır ki validate()
        bunları reddedebilsin.
        """
        if url is None:
            return ""
        url = str(url).strip()
        if not url:
            return ""

        lowered = url.lower()
        # Zaten desteklenen bir protokol varsa olduğu gibi bırak
        if lowered.startswith(("http://", "https://")):
            return url.rstrip("/")

        # Desteklenmeyen protokol varsa olduğu gibi bırak — validate reddeder
        if "://" in url:
            return url

        # Protokol yok — http:// ekle
        return ("http://" + url).rstrip("/")


class TargetValidator:
    """Genel hedef doğrulama (IP veya hostname)."""

    HOSTNAME_RE = re.compile(
        r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    )

    @classmethod
    def is_valid_target(cls, target: str) -> bool:
        """IP veya hostname olarak geçerli mi kontrol eder."""
        if not target:
            return False
        target = target.strip()

        # IP adresi denemesi
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass

        # Hostname denemesi
        return bool(cls.HOSTNAME_RE.match(target))

    @classmethod
    def extract_host(cls, url_or_host: str) -> str:
        """URL'den veya host string'den sadece host kısmını çıkarır."""
        s = url_or_host.strip()
        if "://" in s:
            return urlparse(s).hostname or ""
        # Path varsa kaldır
        return s.split("/")[0].split(":")[0]
