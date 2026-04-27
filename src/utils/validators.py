"""
Siber Savascilar — Giris Dogrulama Araclari
=============================================

SQLMap tarama parametrelerinin dogrulanmasi icin yardimci siniflar.
URL formati, DBMS destegi, parametre sanitizasyonu gibi kontrolleri yonetir.

Guvenlik Notlari (Hafta 6 — Guvenlik Acigi Giderme):
    - SSRF korumasi: Ozel/dahili IP araliklari opsiyonel olarak engellenir.
    - CRLF injection: Header/Cookie degerlerinde satir sonu karakteri reddedilir.
    - Path traversal: output_dir mutlak/normalize edilmis yol disina cikamaz.
    - SQLMap argument injection: Tehlikeli SQLMap bayraklari (--eval, --os-cmd
      vb.) deny-list ile engellenir.
"""

import re
import ipaddress
import os
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

    # ─────────────────────────────────────────────────────────────────────
    # Format Dogrulama
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, str]:
        """
        URL'nin format/sentaks acisindan gecerliligini kontrol eder.

        Bu metod yalnizca FORMAT dogrulamasi yapar. Hedefin dahili/ozel
        bir IP olup olmadigini kontrol etmez. SSRF korumasi icin
        `validate_safe_target()` metodunu kullanin.
        """
        if not url or not isinstance(url, str):
            return False, "URL bos veya gecersiz tip."

        url = url.strip()

        # Whitespace / kontrol karakteri kontrolu (CRLF injection onleme)
        if cls._has_control_chars(url):
            return False, "URL kontrol karakteri (CR/LF/NUL) icermektedir."

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

    # ─────────────────────────────────────────────────────────────────────
    # SSRF / Dahili Hedef Dogrulamasi (CWE-918)
    # ─────────────────────────────────────────────────────────────────────

    # Bilinen tehlikeli host isimleri
    _DANGEROUS_HOSTNAMES = {
        "localhost",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",   # GCP metadata
        "metadata",                    # Docker / cloud metadata
    }

    @classmethod
    def is_private_or_internal_ip(cls, hostname: str) -> bool:
        """
        Verilen hostname veya IP'nin ozel/dahili bir adres olup olmadigini
        kontrol eder. SSRF (CWE-918) saldirilarinin onlenmesi icin kullanilir.

        Engellenen araliklar:
            - 127.0.0.0/8       (loopback)
            - 10.0.0.0/8        (RFC 1918 ozel)
            - 172.16.0.0/12     (RFC 1918 ozel)
            - 192.168.0.0/16    (RFC 1918 ozel)
            - 169.254.0.0/16    (link-local — AWS metadata 169.254.169.254 dahil)
            - 0.0.0.0/8         (yerel ag)
            - ::1/128           (IPv6 loopback)
            - fc00::/7          (IPv6 unique local)
            - fe80::/10         (IPv6 link-local)

        Args:
            hostname: Hostname veya IP adresi.

        Returns:
            True: Dahili/ozel adres. False: Public/disaridan erisilebilir.
        """
        if not hostname:
            return False

        hostname_lower = hostname.lower().strip("[]")

        # Bilinen tehlikeli isimler
        if hostname_lower in cls._DANGEROUS_HOSTNAMES:
            return True

        # IP adresi olarak parse etmeye calis
        try:
            ip = ipaddress.ip_address(hostname_lower)
        except ValueError:
            # Bir IP degil — domain. DNS-rebinding korumasi uygulama
            # katmaninin sorumlulugundadir. Burada sadece literal IP'leri
            # ve ozel hostname'leri kontrol ediyoruz.
            return False

        # IP'nin ozel/dahili olup olmadigini kontrol et
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    @classmethod
    def validate_safe_target(
        cls, url: str, allow_internal: bool = False
    ) -> Tuple[bool, str]:
        """
        URL'yi hem format hem de SSRF guvenligi acisindan dogrular.

        Args:
            url:            Dogrulanacak hedef URL.
            allow_internal: True ise dahili/ozel IP'lere izin verilir.
                            Yerel test ortamlari icin kullanilir; uretim
                            ortaminda asla True olmamalidir.

        Returns:
            (is_safe, message) tuple'i.
        """
        is_valid, msg = cls.validate_url(url)
        if not is_valid:
            return False, msg

        if allow_internal:
            return True, "URL gecerli (dahili hedeflere izin verildi)."

        parsed = urlparse(url)
        if cls.is_private_or_internal_ip(parsed.hostname or ""):
            return False, (
                f"Guvenlik politikasi: '{parsed.hostname}' dahili/ozel bir "
                f"adres oldugu icin tarama hedefi olarak kabul edilmedi. "
                f"Bu kontrol SSRF saldirilarini ve cloud metadata "
                f"sizdirmasini onler. Yerel testler icin "
                f"`allow_internal_targets=True` parametresini acikca verin."
            )

        return True, "URL guvenli ve disa donuk bir hedef."

    @classmethod
    def validate_for_sqli_test(cls, url: str) -> Tuple[bool, str]:
        """
        URL'nin SQL injection testi icin uygun olup olmadigini kontrol eder.
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

    # ─────────────────────────────────────────────────────────────────────
    # Yardimcilar
    # ─────────────────────────────────────────────────────────────────────

    @staticmethod
    def _has_control_chars(value: str) -> bool:
        """Kontrol karakterlerini (CR/LF/NUL) tespit eder."""
        return any(c in value for c in ("\r", "\n", "\x00"))


class ConfigValidator:
    """
    SQLMap yapilandirma parametrelerinin dogrulanmasi.
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

    DBMS_ALIASES = {
        "mssql": "microsoft sql server",
        "db2": "ibm db2",
        "maxdb": "sap maxdb",
        "derby": "apache derby",
        "postgres": "postgresql",
        "pg": "postgresql",
        "mariadb": "mysql",
    }

    VALID_TECHNIQUES = "BEUSTQ"
    RISK_RANGE = (1, 3)
    LEVEL_RANGE = (1, 5)
    VALID_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    # ─────────────────────────────────────────────────────────────────────
    # SQLMap Tehlikeli Argumanlari (CWE-88: Argument Injection)
    # ─────────────────────────────────────────────────────────────────────
    #
    # Bu bayraklar SQLMap'in yetkisiz dosya okuma/yazma, komut calistirma
    # ve diger sistem seviyesi islemler yapabilmesine olanak tanir. Akademik
    # araclarda asla kullanici tarafindan tetiklenmemelidir.
    #
    # Kaynak: SQLMap kullanim kilavuzu (--help) ve OWASP zafiyet listesi.

    BLOCKED_SQLMAP_ARGS = frozenset({
        # Kod / komut calistirma
        "--eval",
        "--os-cmd",
        "--os-shell",
        "--os-pwn",
        "--os-smbrelay",
        "--os-bof",
        "--priv-esc",
        # Dosya islemi
        "--file-read",
        "--file-write",
        "--file-dest",
        "--shared-lib",
        # SQLMap kendisini yeniden yapilandirma / zayiflatma
        "--load-cookies",
        "--proxy-cred",
        "--auth-cred",
        "--auth-file",
        # Wizard mode (interaktif)
        "--wizard",
        # SQLMap'in kendisini guncelleme
        "--update",
        "--purge",
        "--purge-output",
    })

    @classmethod
    def validate_dbms(cls, dbms: str) -> Tuple[bool, str]:
        """DBMS dogrulamasi."""
        if not dbms:
            return True, ""

        dbms_lower = dbms.strip().lower()

        if dbms_lower in cls.DBMS_ALIASES:
            resolved = cls.DBMS_ALIASES[dbms_lower]
            return True, resolved

        if dbms_lower in cls.SUPPORTED_DBMS:
            return True, dbms_lower

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
        """SQLMap injection teknik string'ini dogrular."""
        if not techniques:
            return True, ""

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

        DERINLIKLI SAVUNMA: Asagidaki guvenli karakter beyaz listesi (whitelist)
        haricindeki tum karakterler temizlenir. SQLMap'e parametre olarak
        yalnizca harf, rakam, alt cizgi ve virgul gecirilebilir.

        Onceki versiyondaki "kara liste" yaklasimi tum tehlikeli karakterleri
        kapsamadigi icin shell injection'a karsi tam koruma saglamiyordu.
        """
        if not param:
            return ""

        # Beyaz liste: harf, rakam, alt cizgi, virgul (cok parametre icin)
        allowed = re.compile(r"[^A-Za-z0-9_,]")
        sanitized = allowed.sub("", param)
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

    # ─────────────────────────────────────────────────────────────────────
    # YENI: Header / Cookie / POST Veri Dogrulamasi (CWE-93: CRLF Injection)
    # ─────────────────────────────────────────────────────────────────────

    # Gecerli HTTP header adi: RFC 7230 — token = 1*tchar
    _HEADER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")

    @classmethod
    def validate_header(cls, name: str, value: str) -> Tuple[bool, str]:
        """
        HTTP header adi ve degerinin guvenliligini dogrular.

        - Header adi RFC 7230 token kuralina uymali.
        - Deger CR/LF/NUL karakteri icermemelidir (CRLF injection / response
          splitting saldirilarini onlemek icin).
        """
        if not name or not isinstance(name, str):
            return False, "Header adi bos olamaz."

        if not cls._HEADER_NAME_PATTERN.match(name):
            return False, (
                f"Gecersiz header adi: '{name}'. "
                f"Yalnizca RFC 7230 token karakterleri kabul edilir."
            )

        if value is None:
            return False, "Header degeri None olamaz."

        if not isinstance(value, str):
            return False, "Header degeri string olmalidir."

        if any(c in value for c in ("\r", "\n", "\x00")):
            return False, (
                f"Header '{name}' icin gecersiz deger: CR/LF/NUL karakteri "
                f"icermektedir (CRLF injection riski)."
            )

        return True, "Header gecerli."

    @classmethod
    def validate_cookie(cls, value: str) -> Tuple[bool, str]:
        """Cookie degerinin CR/LF/NUL icermedigini dogrular."""
        if not value:
            return True, ""
        if not isinstance(value, str):
            return False, "Cookie degeri string olmalidir."
        if any(c in value for c in ("\r", "\n", "\x00")):
            return False, (
                "Cookie degeri CR/LF/NUL karakteri icermektedir "
                "(CRLF injection riski)."
            )
        return True, "Cookie gecerli."

    @classmethod
    def validate_data(cls, data: str) -> Tuple[bool, str]:
        """POST veri govdesinin CR/LF/NUL icermedigini dogrular."""
        if not data:
            return True, ""
        if not isinstance(data, str):
            return False, "POST verisi string olmalidir."
        if any(c in data for c in ("\r", "\n", "\x00")):
            return False, (
                "POST verisi CR/LF/NUL karakteri icermektedir "
                "(istek govdesi enjeksiyon riski)."
            )
        return True, "POST verisi gecerli."

    # ─────────────────────────────────────────────────────────────────────
    # YENI: Proxy URL Dogrulamasi
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def validate_proxy(cls, proxy: str) -> Tuple[bool, str]:
        """
        Proxy URL'sinin gecerliligini dogrular.

        Sadece http://, https://, socks4://, socks5:// kabul edilir.
        Kontrol karakterleri reddedilir.
        """
        if not proxy:
            return True, ""

        if not isinstance(proxy, str):
            return False, "Proxy degeri string olmalidir."

        if any(c in proxy for c in ("\r", "\n", "\x00", " ")):
            return False, "Proxy URL'si bosluk veya kontrol karakteri icermemelidir."

        try:
            parsed = urlparse(proxy)
        except Exception as e:
            return False, f"Proxy URL ayristirma hatasi: {str(e)}"

        valid_schemes = ("http", "https", "socks4", "socks5")
        if parsed.scheme.lower() not in valid_schemes:
            return False, (
                f"Gecersiz proxy semasi: '{parsed.scheme}'. "
                f"Gecerli: {', '.join(valid_schemes)}"
            )

        if not parsed.hostname:
            return False, "Proxy URL'sinde host belirtilmemis."

        return True, "Proxy URL'si gecerli."

    # ─────────────────────────────────────────────────────────────────────
    # YENI: Cikti Dizini Dogrulamasi (CWE-22: Path Traversal)
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def validate_output_dir(cls, path: str) -> Tuple[bool, str]:
        """
        SQLMap output dizinin guvenli olup olmadigini dogrular.

        Engellenen durumlar:
            - Path traversal sekansi ('..')
            - Hassas sistem dizinlerine yazma denemeleri (/etc, /root, vb.)
            - NUL karakteri
        """
        if not path:
            return True, ""

        if not isinstance(path, str):
            return False, "Output dizini string olmalidir."

        if "\x00" in path:
            return False, "Output dizininde NUL karakteri olamaz."

        # Path traversal kontrolu — herhangi bir parcasi '..' olamaz
        normalized_slashes = path.replace("\\", "/")
        if ".." in normalized_slashes.split("/"):
            return False, (
                f"Output dizini '..' icermektedir (path traversal riski). "
                f"Mutlak yol veya temiz goreceli yol kullanin."
            )

        # Mutlak yola normalize et
        try:
            normalized = os.path.normpath(os.path.abspath(path))
        except Exception as e:
            return False, f"Output dizini normalize edilemedi: {str(e)}"

        # Hassas sistem dizinlerine yazmayi engelle
        forbidden_prefixes = (
            "/etc",
            "/root",
            "/boot",
            "/proc",
            "/sys",
            "/dev",
            "/var/log",
        )
        for prefix in forbidden_prefixes:
            if normalized == prefix or normalized.startswith(prefix + os.sep):
                return False, (
                    f"Output dizini hassas sistem yoluna yazmaya calisiyor: "
                    f"'{normalized}'. Bu yol engellenmektedir."
                )

        return True, "Output dizini gecerli."

    # ─────────────────────────────────────────────────────────────────────
    # YENI: SQLMap Custom Args Dogrulamasi (CWE-88)
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def validate_custom_args(cls, args: List[str]) -> Tuple[bool, str]:
        """
        Kullanici tarafindan saglanan SQLMap argumanlarinda tehlikeli
        bayrak olup olmadigini kontrol eder.

        BLOCKED_SQLMAP_ARGS listesindeki bir bayrak bulunursa hata doner.

        Args:
            args: SQLMap'e iletilecek argumanlar listesi.

        Returns:
            (is_valid, message) tuple'i.
        """
        if not args:
            return True, ""

        if not isinstance(args, list):
            return False, "custom_args bir liste olmalidir."

        for arg in args:
            if not isinstance(arg, str):
                return False, f"custom_args elemani string olmalidir: {arg!r}"

            # Kontrol karakteri yasak
            if any(c in arg for c in ("\r", "\n", "\x00")):
                return False, (
                    f"custom_args degeri kontrol karakteri icermektedir: {arg!r}"
                )

            # "--bayrak=value" formatini kontrol et — basini al
            flag_part = arg.split("=", 1)[0].strip().lower()

            if flag_part in cls.BLOCKED_SQLMAP_ARGS:
                return False, (
                    f"Guvenlik politikasi: '{flag_part}' bayragi yasaktir. "
                    f"Bu bayrak SQLMap'in dosya okuma/yazma, komut calistirma "
                    f"veya sistem seviyesi erisim saglamasini saglar ve "
                    f"akademik tarama kapsami disindadir."
                )

        return True, "custom_args gecerli."
