"""
Tarama Orkestratörü
====================

Tüm tarayıcı modüllerini koordine eden ana sınıf. Nursena Karaduman'ın
main_v2.py'sindeki mantığın genişletilmiş ve modülerleştirilmiş halidir.

Akış:
    1. URL doğrulanır
    2. Veritabanında scan kaydı oluşturulur
    3. Seçilen tarayıcılar paralel veya sıralı çalıştırılır
    4. Tüm bulgular ScanResult'a toplanır
    5. Sonuç veritabanına yazılır
    6. Rapor üretilir
"""

import time
import urllib3
import requests
from datetime import datetime
from typing import List, Optional, Callable

from .core.models import ScanResult, ScanStatus, Vulnerability
from .core.database import get_db
from .core.validators import URLValidator
from .scanners import SCANNER_REGISTRY, BaseScanner

# requests SSL uyarılarını sustur (test ortamlarında çok çıkıyor)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Varsayılan tarayıcı seti
DEFAULT_MODULES = [
    "ports", "sqli", "xss", "misconfig",
    "sensitive_data", "access_control", "scenarios",
]


class Orchestrator:
    """Tüm tarama akışını yöneten sınıf."""

    def __init__(self, db=None, verbose: bool = True):
        self.db = db or get_db()
        self.verbose = verbose

    def log(self, msg: str):
        if self.verbose:
            print(msg)

    def scan(self,
             target: str,
             modules: Optional[List[str]] = None,
             progress_callback: Optional[Callable] = None) -> ScanResult:
        """
        Tek bir hedef üzerinde seçilen modülleri çalıştırır.

        Args:
            target: Taranacak URL (otomatik normalize edilir)
            modules: Çalıştırılacak modüller. None → DEFAULT_MODULES
            progress_callback: (module_name, current, total) → ilerleme

        Returns:
            ScanResult — tüm sonuçların toplandığı obje
        """
        modules = modules or DEFAULT_MODULES

        # URL normalize + doğrula
        target = URLValidator.normalize(target)
        is_valid, msg = URLValidator.validate(target)

        result = ScanResult(
            target_url=target,
            started_at=datetime.now(),
            status=ScanStatus.RUNNING,
            modules_run=modules,
            scan_config={"modules": modules},
        )

        if not is_valid:
            result.status = ScanStatus.ERROR
            result.error_message = msg
            result.finished_at = datetime.now()
            return result

        # Ön sağlık kontrolü — hedef ulaşılabilir mi?
        self.log(f"Hedef ulaşılabilirlik kontrolü: {target}")
        reachable, reach_msg = self._check_reachable(target)
        if not reachable:
            self.log(f"  ⚠️  {reach_msg}")
            self.log(f"  Tüm HTTP tabanlı modüller muhtemelen 0 bulgu döndürecek.")
            self.log(f"  Tarama yine de denenecek (erken kesme aktif).\n")
            # HTTP'siz çalışabilen modülleri öne al (varsa)
            # Şu an hepsi HTTP gerektiriyor, gelecekte port_scanner için ayrıştırılabilir
        else:
            self.log(f"  ✓ {reach_msg}\n")

        # DB'de scan kaydı oluştur
        scan_id = self.db.create_scan(target, modules)
        result.scan_id = scan_id

        self.log(f"\n{'=' * 60}")
        self.log(f"  SIZMA TESTİ OTOMASYON ARACI — Tarama Başlıyor")
        self.log(f"  Hedef  : {target}")
        self.log(f"  ID     : {scan_id}")
        self.log(f"  Modül  : {', '.join(modules)}")
        self.log(f"{'=' * 60}\n")

        # Her modülü sırayla çalıştır
        total = len(modules)
        for i, module_name in enumerate(modules, 1):
            if module_name not in SCANNER_REGISTRY:
                self.log(f"[{i}/{total}] '{module_name}' bilinmiyor, atlanıyor")
                continue

            self.log(f"[{i}/{total}] {module_name.upper()} çalışıyor...")

            if progress_callback:
                progress_callback(module_name, i, total)

            scanner_class = SCANNER_REGISTRY[module_name]
            try:
                scanner: BaseScanner = scanner_class(verbose=self.verbose)
                start = time.time()
                vulns = scanner.scan(target)
                elapsed = time.time() - start

                result.add_vulnerabilities(vulns)

                # Port scanner için açık port listesini ayrıca tut
                if module_name == "ports":
                    for v in vulns:
                        if "port" in v.details:
                            result.open_ports.append(v.details["port"])

                self.log(f"    → {len(vulns)} bulgu ({elapsed:.1f}sn)\n")

            except Exception as e:
                self.log(f"    [!] {module_name} hatası: {e}\n")

        # Sonlandır
        result.status = ScanStatus.COMPLETED
        result.finished_at = datetime.now()
        result.generate_summary()

        # DB'ye yaz
        self.db.finish_scan(result)

        # Konsol özeti
        self._print_summary(result)

        return result

    def _check_reachable(self, target: str, timeout: int = 5) -> tuple:
        """
        Tarama başlamadan önce hedefin ulaşılabilir olduğunu kontrol eder.

        Returns:
            (reachable: bool, message: str)
        """
        try:
            response = requests.head(target, timeout=timeout, verify=False,
                                     allow_redirects=True)
            return True, f"OK (HTTP {response.status_code})"
        except requests.exceptions.Timeout:
            return False, f"Hedef yanıt vermiyor (timeout). Site çevrimdışı olabilir."
        except requests.exceptions.ConnectionError:
            return False, f"Hedefe bağlanılamadı. DNS veya ağ sorunu olabilir."
        except requests.RequestException as e:
            return False, f"Beklenmeyen hata: {e}"

    def _print_summary(self, result: ScanResult):
        if not self.verbose:
            return
        brk = result.severity_breakdown
        self.log(f"\n{'=' * 60}")
        self.log(f"  TARAMA TAMAMLANDI")
        self.log(f"{'=' * 60}")
        self.log(f"  Toplam zafiyet : {result.vulnerability_count}")
        self.log(f"    🔴 Kritik     : {brk['Critical']}")
        self.log(f"    🟠 Yüksek     : {brk['High']}")
        self.log(f"    🟡 Orta       : {brk['Medium']}")
        self.log(f"    🔵 Düşük      : {brk['Low']}")
        self.log(f"    ⚪ Bilgi      : {brk['Informational']}")
        self.log(f"  Açık port      : {len(result.open_ports)}")
        if result.duration_seconds:
            self.log(f"  Süre           : {result.duration_seconds:.1f} saniye")
        self.log(f"{'=' * 60}\n")
