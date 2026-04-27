"""
Siber Savascilar — SQLMap Yapilandirma Modulu
===============================================

SQLMap komut satiri aracinin parametrelerini yoneten yapilandirma sinifi.
URL, DBMS turu, risk seviyesi, teknikler ve diger tum SQLMap parametrelerini
tek bir sinifta toplayarak komut satiri argumanlarina donusturur.

Desteklenen Veritabani Sistemleri:
    MySQL, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2, ve digerleri.

Desteklenen Injection Teknikleri:
    B = Boolean-based blind
    E = Error-based
    U = Union query-based
    S = Stacked queries
    T = Time-based blind
    Q = Inline queries
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import copy

from src.utils.validators import URLValidator, ConfigValidator


# ─────────────────────────────────────────────────────────────────────────────
# SQLMap Teknik Eslemeleri
# ─────────────────────────────────────────────────────────────────────────────

TECHNIQUE_MAP = {
    "B": "Boolean-based blind",
    "E": "Error-based",
    "U": "Union query-based",
    "S": "Stacked queries",
    "T": "Time-based blind",
    "Q": "Inline queries",
}


# ─────────────────────────────────────────────────────────────────────────────
# Yapilandirma Sinifi
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SQLMapConfig:
    """
    SQLMap tarama yapilandirma sinifi.
    
    Tum SQLMap parametrelerini tek bir yerde toplayan ve bu parametreleri
    komut satiri argumanlarina donusturen veri sinifi.
    
    Attributes:
        target_url: Hedef URL (zorunlu). Orn: "http://example.com/page?id=1"
        
        # ── Hedef Parametreleri ──
        parameter:     Test edilecek belirli parametre(ler). Orn: "id,username"
        data:          POST verisi. Orn: "username=admin&password=test"
        method:        HTTP metodu (GET/POST). Varsayilan: otomatik tespit.
        cookie:        HTTP Cookie degeri. Orn: "PHPSESSID=abc123"
        headers:       Ek HTTP basliklari. Dict formatinda.
        
        # ── Veritabani ──
        dbms:          Hedef DBMS. Orn: "mysql", "postgresql", "mssql"
        
        # ── Test Parametreleri ──
        level:         Test seviyesi (1-5). 1=Basit, 5=En kapsamli.
        risk:          Risk seviyesi (1-3). 1=Guvenli, 3=OR tabanli testler dahil.
        techniques:    Kullanilacak teknikler. Orn: "BEU" (Boolean, Error, Union).
        
        # ── Tarama Secenekleri ──
        forms:         Form alanlarini otomatik kesfet ve test et.
        crawl_depth:   Sitede link takibi derinligi (0=kapali).
        threads:       Es zamanli istek sayisi (1-10).
        timeout:       Istek zaman asimi (saniye).
        retries:       Basarisiz isteklerin tekrar deneme sayisi.
        
        # ── Cikti Secenekleri ──
        verbose:       Detay seviyesi (0-6).
        output_dir:    Sonuc dizini yolu.
        batch:         Otomatik mod (tum sorulari varsayilan yanitla).
        flush_session: Onceki oturum verilerini temizle.
        
        # ── Guvenlik ──
        tamper:        Tamper script'leri. Orn: ["space2comment", "randomcase"]
        random_agent:  Rastgele User-Agent kullan.
        proxy:         Proxy adresi. Orn: "http://127.0.0.1:8080"
        tor:           Tor agini kullan.
    """

    # ── Zorunlu ──
    target_url: str = ""

    # ── Hedef Parametreleri ──
    parameter: str = ""
    data: str = ""
    method: str = ""
    cookie: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    # ── Veritabani ──
    dbms: str = ""

    # ── Test Parametreleri ──
    level: int = 1
    risk: int = 1
    techniques: str = ""  # Bos = tum teknikler

    # ── Tarama Secenekleri ──
    forms: bool = False
    crawl_depth: int = 0
    threads: int = 1
    timeout: int = 30
    retries: int = 3

    # ── Cikti Secenekleri ──
    verbose: int = 1
    output_dir: str = ""
    batch: bool = True
    flush_session: bool = False

    # ── Guvenlik / Evasion ──
    tamper: List[str] = field(default_factory=list)
    random_agent: bool = True
    proxy: str = ""
    tor: bool = False

    # ── Ileri Duzey ──
    custom_args: List[str] = field(default_factory=list)

    # ── Guvenlik Bayraklari (Hafta 6) ──
    # SSRF korumasi: Dahili/ozel IP'lere tarama izni icin acikca True yapin.
    allow_internal_targets: bool = False

    # ─────────────────────────────────────────────────────────────────────
    # Dogrulama
    # ─────────────────────────────────────────────────────────────────────

    def validate(self) -> List[str]:
        """
        Yapilandirmanin gecerliligini kontrol eder.
        
        Returns:
            Hata mesajlarinin listesi. Bos liste = gecerli yapilandirma.
            
        Raises:
            ValueError: Kritik hatalar varsa (target_url bos gibi).
        """
        errors = []

        # URL kontrolu (zorunlu) — Format + SSRF koruması
        if not self.target_url:
            errors.append("target_url zorunludur.")
        else:
            is_valid, msg = URLValidator.validate_safe_target(
                self.target_url,
                allow_internal=self.allow_internal_targets,
            )
            if not is_valid:
                errors.append(f"URL hatasi: {msg}")

        # DBMS kontrolu
        if self.dbms:
            is_valid, msg = ConfigValidator.validate_dbms(self.dbms)
            if not is_valid:
                errors.append(f"DBMS hatasi: {msg}")

        # Level kontrolu
        is_valid, msg = ConfigValidator.validate_level(self.level)
        if not is_valid:
            errors.append(f"Level hatasi: {msg}")

        # Risk kontrolu
        is_valid, msg = ConfigValidator.validate_risk(self.risk)
        if not is_valid:
            errors.append(f"Risk hatasi: {msg}")

        # Teknikler kontrolu
        if self.techniques:
            is_valid, msg = ConfigValidator.validate_techniques(self.techniques)
            if not is_valid:
                errors.append(f"Teknikler hatasi: {msg}")

        # Method kontrolu
        if self.method:
            is_valid, msg = ConfigValidator.validate_method(self.method)
            if not is_valid:
                errors.append(f"Metod hatasi: {msg}")

        # Threads kontrolu
        if self.threads < 1 or self.threads > 10:
            errors.append("Threads 1-10 arasinda olmalidir.")

        # Timeout kontrolu
        if self.timeout:
            is_valid, msg = ConfigValidator.validate_timeout(self.timeout)
            if not is_valid:
                errors.append(f"Timeout hatasi: {msg}")

        # ── YENI: Hafta 6 Guvenlik Kontrolleri ──

        # Cookie kontrolu (CRLF injection)
        if self.cookie:
            is_valid, msg = ConfigValidator.validate_cookie(self.cookie)
            if not is_valid:
                errors.append(f"Cookie hatasi: {msg}")

        # POST data kontrolu
        if self.data:
            is_valid, msg = ConfigValidator.validate_data(self.data)
            if not is_valid:
                errors.append(f"Data hatasi: {msg}")

        # Header kontrolu
        if self.headers:
            for h_name, h_value in self.headers.items():
                is_valid, msg = ConfigValidator.validate_header(h_name, h_value)
                if not is_valid:
                    errors.append(f"Header hatasi: {msg}")

        # Proxy kontrolu
        if self.proxy:
            is_valid, msg = ConfigValidator.validate_proxy(self.proxy)
            if not is_valid:
                errors.append(f"Proxy hatasi: {msg}")

        # Output dizini kontrolu (path traversal)
        if self.output_dir:
            is_valid, msg = ConfigValidator.validate_output_dir(self.output_dir)
            if not is_valid:
                errors.append(f"Output dizini hatasi: {msg}")

        # Custom args kontrolu (argument injection)
        if self.custom_args:
            is_valid, msg = ConfigValidator.validate_custom_args(self.custom_args)
            if not is_valid:
                errors.append(f"custom_args hatasi: {msg}")

        return errors

    def is_valid(self) -> bool:
        """Yapilandirma gecerli mi?"""
        return len(self.validate()) == 0

    # ─────────────────────────────────────────────────────────────────────
    # Komut Satiri Donusumu
    # ─────────────────────────────────────────────────────────────────────

    def to_command_args(self) -> List[str]:
        """
        Yapilandirmayi SQLMap komut satiri argumanlarina donusturur.
        
        Returns:
            SQLMap arguman listesi.
            Orn: ["-u", "http://example.com?id=1", "--batch", "--level=3", ...]
            
        Raises:
            ValueError: Yapilandirma gecerli degilse.
        """
        errors = self.validate()
        if errors:
            raise ValueError(
                "Gecersiz yapilandirma:\n" + "\n".join(f"  - {e}" for e in errors)
            )

        args = []

        # ── Hedef ──
        args.extend(["-u", self.target_url])

        if self.parameter:
            args.extend(["-p", ConfigValidator.sanitize_parameter(self.parameter)])

        if self.data:
            args.extend(["--data", self.data])

        if self.method:
            args.extend(["--method", self.method.upper()])

        if self.cookie:
            args.extend(["--cookie", self.cookie])

        if self.headers:
            for key, value in self.headers.items():
                args.extend(["--header", f"{key}: {value}"])

        # ── Veritabani ──
        if self.dbms:
            # DBMS'i normalize et
            is_valid, normalized = ConfigValidator.validate_dbms(self.dbms)
            if is_valid and normalized:
                args.extend(["--dbms", normalized])

        # ── Test Parametreleri ──
        if self.level != 1:
            args.extend(["--level", str(self.level)])

        if self.risk != 1:
            args.extend(["--risk", str(self.risk)])

        if self.techniques:
            args.extend(["--technique", self.techniques.upper()])

        # ── Tarama Secenekleri ──
        if self.forms:
            args.append("--forms")

        if self.crawl_depth > 0:
            args.extend(["--crawl", str(self.crawl_depth)])

        if self.threads != 1:
            args.extend(["--threads", str(self.threads)])

        if self.timeout != 30:
            args.extend(["--timeout", str(self.timeout)])

        if self.retries != 3:
            args.extend(["--retries", str(self.retries)])

        # ── Cikti ──
        if self.verbose != 1:
            args.extend(["-v", str(self.verbose)])

        if self.output_dir:
            args.extend(["--output-dir", self.output_dir])

        if self.batch:
            args.append("--batch")

        if self.flush_session:
            args.append("--flush-session")

        # ── Guvenlik / Evasion ──
        if self.tamper:
            args.extend(["--tamper", ",".join(self.tamper)])

        if self.random_agent:
            args.append("--random-agent")

        if self.proxy:
            args.extend(["--proxy", self.proxy])

        if self.tor:
            args.append("--tor")

        # ── Ozel argumanlar ──
        args.extend(self.custom_args)

        return args

    def to_command_string(self) -> str:
        """
        Tam SQLMap komut satirini string olarak doner.
        
        Returns:
            Orn: "sqlmap -u 'http://example.com?id=1' --batch --level=3"
        """
        args = self.to_command_args()
        # URL ve degerleri tirnak icine al
        quoted_args = []
        skip_next = False
        for i, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if arg.startswith("-") and i + 1 < len(args) and not args[i + 1].startswith("-"):
                quoted_args.append(f"{arg} '{args[i + 1]}'")
                skip_next = True
            else:
                quoted_args.append(arg)
        return "sqlmap " + " ".join(quoted_args)

    # ─────────────────────────────────────────────────────────────────────
    # Serializasyon
    # ─────────────────────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Yapilandirmayi sozluge donusturur."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SQLMapConfig":
        """
        Sozlukten yapilandirma nesnesi olusturur.
        
        Args:
            data: Yapilandirma verileri sozlugu.
            
        Returns:
            SQLMapConfig nesnesi.
        """
        # Sadece tanimli alanlari al
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def copy(self) -> "SQLMapConfig":
        """Yapilandirmanin derin kopyasini doner."""
        return copy.deepcopy(self)

    # ─────────────────────────────────────────────────────────────────────
    # Hazir Profiller (Factory Methods)
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def quick_scan(cls, url: str, dbms: str = "") -> "SQLMapConfig":
        """
        Hizli tarama profili — temel kontroller, dusuk risk.
        
        Kullanim: Ilk kesif asamasi, hizli sonuc.
        """
        return cls(
            target_url=url,
            dbms=dbms,
            level=1,
            risk=1,
            techniques="BE",  # Boolean + Error (en hizlilar)
            threads=4,
            timeout=15,
            batch=True,
            random_agent=True,
        )

    @classmethod
    def standard_scan(cls, url: str, dbms: str = "") -> "SQLMapConfig":
        """
        Standart tarama profili — dengeli seviye ve risk.
        
        Kullanim: Gunluk taramalar, orta derinlikte analiz.
        """
        return cls(
            target_url=url,
            dbms=dbms,
            level=3,
            risk=2,
            techniques="BEUST",
            threads=3,
            timeout=30,
            batch=True,
            random_agent=True,
        )

    @classmethod
    def deep_scan(cls, url: str, dbms: str = "") -> "SQLMapConfig":
        """
        Derin tarama profili — en kapsamli test,  yuksek risk.
        
        Kullanim: Detayli analiz, tum tekniklerin denenmesi.
        ⚠️ Dikkat: Yavas calisir ve hedef sisteme yuk bindirebilir.
        """
        return cls(
            target_url=url,
            dbms=dbms,
            level=5,
            risk=3,
            techniques="BEUSTQ",
            threads=1,
            timeout=60,
            batch=True,
            random_agent=True,
            forms=True,
            crawl_depth=2,
        )

    @classmethod
    def post_scan(cls, url: str, post_data: str, dbms: str = "") -> "SQLMapConfig":
        """
        POST parametreli tarama profili.
        
        Args:
            url:       Hedef URL.
            post_data: POST verisi. Orn: "username=admin&password=test"
            dbms:      Veritabani turu (opsiyonel).
        """
        return cls(
            target_url=url,
            data=post_data,
            method="POST",
            dbms=dbms,
            level=3,
            risk=2,
            techniques="BEUST",
            threads=3,
            batch=True,
            random_agent=True,
        )

    # ─────────────────────────────────────────────────────────────────────
    # Temsil
    # ─────────────────────────────────────────────────────────────────────

    def __str__(self) -> str:
        techniques_desc = ""
        if self.techniques:
            descs = [
                TECHNIQUE_MAP.get(t, t) for t in self.techniques.upper()
            ]
            techniques_desc = ", ".join(descs)
        else:
            techniques_desc = "Tumu"

        return (
            f"SQLMap Yapilandirma:\n"
            f"  🎯 Hedef: {self.target_url}\n"
            f"  🗄️  DBMS: {self.dbms or 'Otomatik Tespit'}\n"
            f"  📊 Level: {self.level} | Risk: {self.risk}\n"
            f"  🔧 Teknikler: {techniques_desc}\n"
            f"  🧵 Threads: {self.threads} | Timeout: {self.timeout}s\n"
            f"  🤖 Batch: {self.batch} | Random Agent: {self.random_agent}"
        )
