"""
Siber Savascilar — Giris Dogrulama Araclari
=============================================

SQLMap tarama parametrelerinin dogrulanmasi icin yardimci siniflar.
URL formati, DBMS destegi, parametre sanitizasyonu gibi kontrolleri yonetir.
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import List, Optional, Tuple


class URLValidator:
    """
    URL dogrulama ve analiz sinifi.
    
    SQLMap'e gonderilecek hedef URL'lerin dogrulugunu kontrol eder
    ve SQL injection testi icin uygun olup olmadigini degerlendirir.
    """

    # Desteklenen protokoller
    SUPPORTED_SCHEMES = ("http", "https")

    # URL'de olmasi beklenen test parametresi pattern'leri
    INJECTABLE_PARAM_PATTERNS = [
        r"[?&]\w+=\w*",          # Standart query string parametresi
        r"[?&]\w+=\d+",          # Sayisal parametre (en yaygin injection hedefi)
    ]

    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, str]:
        """
        URL'nin gecerliligini kontrol eder.
        
        Args:
            url: Dogrulanacak URL string'i.
            
        Returns:
            (is_valid, message) tuple'i.
            
        Examples:
            >>> URLValidator.validate_url("http://example.com/page?id=1")
            (True, "URL gecerli.")
            >>> URLValidator.validate_url("ftp://example.com")
            (False, "Desteklenmeyen protokol: ftp. Desteklenen: http, https")
        """
        if not url or not isinstance(url, str):
            return False, "URL bos veya gecersiz tip."

        url = url.strip()

        # URL parse
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"URL ayristirma hatasi: {str(e)}"

        # Protokol kontrolu
        if not parsed.scheme:
            return False, "URL'de protokol belirtilmemis. Ornek: http:// veya https://"

        if parsed.scheme.lower() not in cls.SUPPORTED_SCHEMES:
            return False, (
                f"Desteklenmeyen protokol: {parsed.scheme}. "
                f"Desteklenen: {', '.join(cls.SUPPORTED_SCHEMES)}"
            )

        # Host kontrolu
        if not parsed.hostname:
            return False, "URL'de gecerli bir host (domain/IP) bulunamadi."

        # Temel hostname format kontrolu
        hostname = parsed.hostname
        # IP adresi mi yoksa domain mi?
        ip_pattern = re.compile(
            r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        )
        ip_match = ip_pattern.match(hostname)

        if ip_match:
            # IP adresi dogrulama
            octets = [int(g) for g in ip_match.groups()]
            if any(o < 0 or o > 255 for o in octets):
                return False, f"Gecersiz IP adresi: {hostname}"
        else:
            # Domain name dogrulama
            domain_pattern = re.compile(
                r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
            )
            if hostname != "localhost" and not domain_pattern.match(hostname):
                return False, f"Gecersiz domain adi: {hostname}"

        return True, "URL gecerli."

    @classmethod
    def has_parameters(cls, url: str) -> bool:
        """URL'de query string parametresi var mi kontrol eder."""
        parsed = urlparse(url)
        return bool(parsed.query)

    @classmethod
    def extract_parameters(cls, url: str) -> dict:
        """URL'den query string parametrelerini cikarir."""
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    @classmethod
    def validate_for_sqli_test(cls, url: str) -> Tuple[bool, str]:
        """
        URL'nin SQL injection testi icin uygun olup olmadigini kontrol eder.
        
        Uygunluk kriterleri:
        - Gecerli URL formati
        - Query string parametresi bulunmasi (onerilen)
        
        Args:
            url: Test edilecek URL.
            
        Returns:
            (is_suitable, message) tuple'i.
        """
        is_valid, msg = cls.validate_url(url)
        if not is_valid:
            return False, msg

        if not cls.has_parameters(url):
            return True, (
                "⚠️  URL'de query string parametresi bulunamadi. "
                "SQLMap, --forms veya --crawl secenekleriyle form tabanli "
                "parametreleri de tarayabilir. Yine de devam edebilirsiniz."
            )

        params = cls.extract_parameters(url)
        param_names = list(params.keys())
        return True, (
            f"URL, SQL injection testi icin uygun. "
            f"Bulunan parametreler: {', '.join(param_names)}"
        )


class ConfigValidator:
    """
    SQLMap yapilandirma parametrelerinin dogrulanmasi.
    
    Kullanicinin girdigi yapilandirma degerlerinin SQLMap tarafindan
    desteklenip desteklenmedigini kontrol eder.
    """

    # SQLMap'in destekledigi DBMS listesi
    SUPPORTED_DBMS = [
        "mysql",
        "oracle", 
        "postgresql",
        "microsoft sql server",
        "mssql",
        "sqlite",
        "ibm db2",
        "db2",
        "firebird",
        "sybase",
        "sap maxdb",
        "maxdb",
        "hsqldb",
        "h2",
        "monetdb",
        "apache derby",
        "derby",
        "vertica",
        "mckoi",
        "presto",
        "altibase",
        "mimersql",
        "cratedb",
        "cubrid",
        "cache",
        "extremedb",
        "frontbase",
        "raima",
        "virtuoso",
    ]

    # DBMS kisaltma eslemeleri
    DBMS_ALIASES = {
        "mssql": "microsoft sql server",
        "db2": "ibm db2",
        "maxdb": "sap maxdb",
        "derby": "apache derby",
        "postgres": "postgresql",
        "pg": "postgresql",
        "mariadb": "mysql",
    }

    # SQLMap injection teknikleri
    VALID_TECHNIQUES = "BEUSTQ"

    # Risk seviye araligi
    RISK_RANGE = (1, 3)

    # Level araligi
    LEVEL_RANGE = (1, 5)

    # Gecerli HTTP metodlari
    VALID_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    @classmethod
    def validate_dbms(cls, dbms: str) -> Tuple[bool, str]:
        """
        DBMS degerinin SQLMap tarafindan desteklenip desteklenmedigini kontrol eder.
        
        Args:
            dbms: Veritabani sistemi adi.
            
        Returns:
            (is_valid, normalized_dbms_or_error_message) tuple'i.
        """
        if not dbms:
            return True, ""  # Bos birakilabilir (SQLMap otomatik tespit eder)

        dbms_lower = dbms.strip().lower()

        # Alias kontrolu
        if dbms_lower in cls.DBMS_ALIASES:
            resolved = cls.DBMS_ALIASES[dbms_lower]
            return True, resolved

        # Dogrudan destek kontrolu
        if dbms_lower in cls.SUPPORTED_DBMS:
            return True, dbms_lower

        # Yakin eslesme onerisi
        suggestions = [
            d for d in cls.SUPPORTED_DBMS
            if dbms_lower in d or d in dbms_lower
        ]
        if suggestions:
            return False, (
                f"'{dbms}' desteklenmiyor. Sunu mu demek istediniz: "
                f"{', '.join(suggestions)}"
            )

        return False, (
            f"'{dbms}' desteklenmiyor. Desteklenen DBMS'ler: "
            f"MySQL, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2, vb."
        )

    @classmethod
    def validate_techniques(cls, techniques: str) -> Tuple[bool, str]:
        """
        SQLMap injection teknik string'ini dogrular.
        
        Args:
            techniques: Teknik harfleri (or: "BEU", "BEUSTQ").
            
        Returns:
            (is_valid, message) tuple'i.
        """
        if not techniques:
            return True, ""  # Bos = tum teknikler

        techniques_upper = techniques.upper()
        invalid_chars = [
            c for c in techniques_upper if c not in cls.VALID_TECHNIQUES
        ]

        if invalid_chars:
            return False, (
                f"Gecersiz teknik karakterleri: {', '.join(invalid_chars)}. "
                f"Gecerli teknikler: "
                f"B=Boolean-based, E=Error-based, U=Union, "
                f"S=Stacked, T=Time-based, Q=Inline"
            )

        return True, f"Secilen teknikler: {techniques_upper}"

    @classmethod
    def validate_risk(cls, risk: int) -> Tuple[bool, str]:
        """Risk seviyesini dogrular (1-3)."""
        if not isinstance(risk, int):
            return False, "Risk degeri tam sayi olmalidir."

        min_r, max_r = cls.RISK_RANGE
        if risk < min_r or risk > max_r:
            return False, (
                f"Risk degeri {min_r}-{max_r} arasinda olmalidir. "
                f"Verilen: {risk}. "
                f"(1=Dusuk risk, 2=Orta, 3=Yuksek — OR tabanli testler dahil)"
            )
        return True, f"Risk seviyesi: {risk}"

    @classmethod
    def validate_level(cls, level: int) -> Tuple[bool, str]:
        """Test seviyesini dogrular (1-5)."""
        if not isinstance(level, int):
            return False, "Level degeri tam sayi olmalidir."

        min_l, max_l = cls.LEVEL_RANGE
        if level < min_l or level > max_l:
            return False, (
                f"Level degeri {min_l}-{max_l} arasinda olmalidir. "
                f"Verilen: {level}. "
                f"(1=Temel testler, 5=En kapsamli — Cookie/Header testleri dahil)"
            )
        return True, f"Test seviyesi: {level}"

    @classmethod
    def validate_method(cls, method: str) -> Tuple[bool, str]:
        """HTTP metodunu dogrular."""
        if not method:
            return True, ""

        method_upper = method.upper()
        if method_upper not in cls.VALID_METHODS:
            return False, (
                f"Gecersiz HTTP metodu: {method}. "
                f"Gecerli metodlar: {', '.join(cls.VALID_METHODS)}"
            )
        return True, method_upper

    @classmethod
    def sanitize_parameter(cls, param: str) -> str:
        """
        Parametre degerini sanitize eder.
        Tehlikeli shell karakterlerini temizler.
        
        Args:
            param: Ham parametre string'i.
            
        Returns:
            Temizlenmis parametre string'i.
        """
        if not param:
            return ""

        # Shell injection'a karsi tehlikeli karakterleri kaldir
        dangerous_chars = [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "\\", "\n", "\r"]
        sanitized = param
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")

        return sanitized.strip()

    @classmethod
    def validate_timeout(cls, timeout: int) -> Tuple[bool, str]:
        """Timeout degerini dogrular (saniye cinsinden)."""
        if not isinstance(timeout, (int, float)):
            return False, "Timeout degeri sayisal olmalidir."
        if timeout < 1:
            return False, "Timeout en az 1 saniye olmalidir."
        if timeout > 3600:
            return False, "Timeout en fazla 3600 saniye (1 saat) olabilir."
        return True, f"Timeout: {timeout} saniye"
