"""
Siber Savascilar — SQLMap Tarayici Motor
==========================================

SQLMap aracini subprocess ile calistiran ana tarayici modul.
Tarama baslatma, durma, durum sorgulama ve sonuc toplama islemlerini yonetir.

Kullanim:
    from src.scanners.sqlmap_scanner import SQLMapScanner
    from src.config.sqlmap_config import SQLMapConfig
    
    scanner = SQLMapScanner()
    config = SQLMapConfig.quick_scan("http://example.com/page?id=1", dbms="mysql")
    result = scanner.scan(config)
    
    if result.is_vulnerable:
        print(result.generate_summary())
        # Raporlama modulune aktar
        report_data = result.to_report_dict()

Gereksinimler:
    - SQLMap'in sistemde kurulu ve PATH'te erisilebilir olmasi
    - Python >= 3.8
"""

import subprocess
import shutil
import tempfile
import os
import uuid
import signal
import logging
import time
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path

from src.config.sqlmap_config import SQLMapConfig
from src.parsers.sqlmap_parser import SQLMapOutputParser
from src.models.scan_result import ScanResult, ScanStatus


# ─────────────────────────────────────────────────────────────────────────────
# Logger Yapilandirmasi
# ─────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("siber_savascilar.sqlmap_scanner")


# ─────────────────────────────────────────────────────────────────────────────
# Ozel Hatalar
# ─────────────────────────────────────────────────────────────────────────────

class SQLMapNotFoundError(Exception):
    """SQLMap sistemde bulunamadi hatasi."""
    pass


class SQLMapScanError(Exception):
    """SQLMap tarama sirasinda olusan hata."""
    pass


class SQLMapTimeoutError(Exception):
    """SQLMap tarama zaman asimi hatasi."""
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Ana Tarayici Sinif
# ─────────────────────────────────────────────────────────────────────────────

class SQLMapScanner:
    """
    SQLMap aracini subprocess ile calistiran ana tarayici sinif.
    
    Bu sinif, SQLMap'i komut satirindan calistirarak SQL injection
    zafiyetlerini tespit eder ve sonuclari yapilandirilmis veri
    modeli olarak doner.
    
    Attributes:
        sqlmap_path:    SQLMap calistirilabilir dosyasinin yolu.
        default_timeout: Varsayilan tarama zaman asimi (saniye).
        parser:         SQLMap cikti ayristirici nesnesi.
        _active_scans:  Devam eden tarama sureclerinin sozlugu.
    """

    # Varsayilan tarama suresi limiti (saniye)
    DEFAULT_SCAN_TIMEOUT = 300  # 5 dakika

    # SQLMap'i bulma yollari
    SQLMAP_EXECUTABLES = ["sqlmap", "sqlmap.py", "python sqlmap.py"]

    def __init__(
        self,
        sqlmap_path: Optional[str] = None,
        default_timeout: int = DEFAULT_SCAN_TIMEOUT,
    ):
        """
        SQLMapScanner'i baslatir.
        
        Args:
            sqlmap_path:    SQLMap yolu (None ise otomatik arar).
            default_timeout: Varsayilan tarama zaman asimi (saniye).
        """
        self.sqlmap_path = sqlmap_path or self._find_sqlmap()
        self.default_timeout = default_timeout
        self.parser = SQLMapOutputParser()
        self._active_scans: Dict[str, subprocess.Popen] = {}

        logger.info(
            "SQLMapScanner baslatildi. SQLMap yolu: %s",
            self.sqlmap_path or "Bulunamadi"
        )

    # ─────────────────────────────────────────────────────────────────────
    # SQLMap Kontrol
    # ─────────────────────────────────────────────────────────────────────

    def _find_sqlmap(self) -> Optional[str]:
        """
        Sistemde SQLMap'i arar.
        
        Returns:
            SQLMap'in tam yolu veya None.
        """
        # 1. PATH'te ara
        sqlmap_path = shutil.which("sqlmap")
        if sqlmap_path:
            return sqlmap_path

        # 2. Yaygin kurulum konumlarini kontrol et
        common_paths = [
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/usr/share/sqlmap/sqlmap.py",
            "/opt/sqlmap/sqlmap.py",
            os.path.expanduser("~/sqlmap/sqlmap.py"),
            os.path.expanduser("~/.local/bin/sqlmap"),
        ]

        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path

        # 3. Python modulu olarak kontrol et
        try:
            result = subprocess.run(
                ["python3", "-m", "sqlmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return "python3 -m sqlmap"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    def check_sqlmap_installed(self) -> bool:
        """
        SQLMap'in sistemde kurulu ve calisir durumda olup olmadigini kontrol eder.
        
        Returns:
            True: SQLMap kullanilabilir durumda.
            False: SQLMap bulunamadi veya calistirilamadi.
        """
        if not self.sqlmap_path:
            return False

        try:
            result = subprocess.run(
                self._build_base_command() + ["--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def get_sqlmap_version(self) -> Optional[str]:
        """SQLMap surum bilgisini doner."""
        if not self.check_sqlmap_installed():
            return None

        try:
            result = subprocess.run(
                self._build_base_command() + ["--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────────────
    # Senkron Tarama
    # ─────────────────────────────────────────────────────────────────────

    def scan(
        self,
        config: SQLMapConfig,
        timeout: Optional[int] = None,
    ) -> ScanResult:
        """
        Verilen yapilandirma ile senkron SQLMap taramasi baslatir.
        
        Tarama tamamlanana kadar bekler ve sonuclari ScanResult olarak doner.
        Raporlama modulune dogrudan aktarilabilecek formatta cikti uretir.
        
        Args:
            config:  SQLMap tarama yapilandirmasi.
            timeout: Tarama zaman asimi (saniye). None ise default_timeout kullanilir.
            
        Returns:
            ScanResult: Tarama sonuclari.
            
        Raises:
            SQLMapNotFoundError: SQLMap bulunamazsa.
            ValueError: Gecersiz yapilandirma varsa.
            
        Example:
            >>> config = SQLMapConfig.quick_scan("http://target.com/page?id=1")
            >>> result = scanner.scan(config)
            >>> print(result.is_vulnerable)
            True
            >>> print(result.to_report_dict())
            {...}
        """
        # SQLMap kontrolu
        if not self.sqlmap_path:
            raise SQLMapNotFoundError(
                "SQLMap sistemde bulunamadi. Lutfen SQLMap'i kurun:\n"
                "  pip install sqlmap\n"
                "  veya: apt install sqlmap (Linux)\n"
                "  veya: brew install sqlmap (macOS)"
            )

        # Yapilandirma dogrulama
        errors = config.validate()
        if errors:
            raise ValueError(
                "Gecersiz yapilandirma:\n" +
                "\n".join(f"  - {e}" for e in errors)
            )

        # Timeout belirleme
        scan_timeout = timeout or self.default_timeout

        # Gecici output dizini
        temp_output_dir = tempfile.mkdtemp(prefix="sqlmap_scan_")

        # Config'e output dizini ekle
        scan_config = config.copy()
        if not scan_config.output_dir:
            scan_config.output_dir = temp_output_dir

        # Komut olustur
        cmd = self._build_base_command() + scan_config.to_command_args()
        cmd_string = " ".join(cmd)

        logger.info("SQLMap taramasi baslatiliyor: %s", config.target_url)
        logger.debug("Komut: %s", cmd_string)

        # ScanResult baslat
        result = ScanResult(
            target_url=config.target_url,
            started_at=datetime.now(),
            scan_config=config.to_dict(),
            command_line=cmd_string,
        )

        try:
            # Subprocess ile calistir
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=scan_timeout,
                env=self._get_clean_env(),
            )

            result.finished_at = datetime.now()

            # Ciktiyi al
            raw_output = process.stdout
            if process.stderr:
                raw_output += "\n--- STDERR ---\n" + process.stderr

            result.raw_output = raw_output

            # Ciktiyi parse et
            parsed = self.parser.parse_full_output(
                raw_output,
                config_dict=config.to_dict(),
            )

            # Parsed sonuclari result'a aktar
            result.vulnerabilities = parsed.vulnerabilities
            result.sqlmap_version = parsed.sqlmap_version
            result.status = ScanStatus.COMPLETED

            if parsed.error_message and not result.vulnerabilities:
                result.status = ScanStatus.ERROR
                result.error_message = parsed.error_message

            logger.info(
                "Tarama tamamlandi: %s — %d zafiyet bulundu",
                config.target_url,
                result.vulnerability_count,
            )

        except subprocess.TimeoutExpired:
            result.finished_at = datetime.now()
            result.status = ScanStatus.TIMEOUT
            result.error_message = (
                f"Tarama {scan_timeout} saniye icinde tamamlanamadi."
            )
            logger.warning("Tarama zaman asimi: %s", config.target_url)

        except FileNotFoundError:
            result.finished_at = datetime.now()
            result.status = ScanStatus.ERROR
            result.error_message = (
                f"SQLMap calistirilamadi: {self.sqlmap_path}"
            )
            logger.error("SQLMap calistirilamadi: %s", self.sqlmap_path)

        except Exception as e:
            result.finished_at = datetime.now()
            result.status = ScanStatus.ERROR
            result.error_message = f"Beklenmeyen hata: {str(e)}"
            logger.exception("Tarama sirasinda beklenmeyen hata")

        finally:
            # Output dizininden ek sonuclari topla
            try:
                if os.path.isdir(temp_output_dir):
                    dir_result = self.parser.parse_target_results(
                        temp_output_dir,
                        target_url=config.target_url,
                    )
                    # Konsol parse'dan gelmeyip dosyadan gelen zafiyetleri ekle
                    existing_titles = {v.title for v in result.vulnerabilities}
                    for v in dir_result.vulnerabilities:
                        if v.title not in existing_titles:
                            result.vulnerabilities.append(v)
            except Exception:
                pass

            # Gecici dizini temizle
            self._cleanup_temp_dir(temp_output_dir)

        # Ozet olustur
        result.generate_summary()

        return result

    # ─────────────────────────────────────────────────────────────────────
    # Asenkron Tarama
    # ─────────────────────────────────────────────────────────────────────

    def scan_async(self, config: SQLMapConfig) -> str:
        """
        Asenkron SQLMap taramasi baslatir.
        
        Tarama arka planda calisir. Task ID ile durum sorgulanabilir
        ve sonuclar alinabilir.
        
        Args:
            config: SQLMap tarama yapilandirmasi.
            
        Returns:
            task_id: Takip icin benzersiz gorev kimligi.
            
        Raises:
            SQLMapNotFoundError: SQLMap bulunamazsa.
        """
        if not self.sqlmap_path:
            raise SQLMapNotFoundError("SQLMap sistemde bulunamadi.")

        errors = config.validate()
        if errors:
            raise ValueError(
                "Gecersiz yapilandirma:\n" +
                "\n".join(f"  - {e}" for e in errors)
            )

        task_id = str(uuid.uuid4())[:8]

        # Gecici dizin
        temp_dir = tempfile.mkdtemp(prefix=f"sqlmap_{task_id}_")
        scan_config = config.copy()
        scan_config.output_dir = temp_dir

        cmd = self._build_base_command() + scan_config.to_command_args()

        logger.info("Asenkron tarama baslatiliyor [%s]: %s", task_id, config.target_url)

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self._get_clean_env(),
            )
            self._active_scans[task_id] = {
                "process": process,
                "config": config.to_dict(),
                "target_url": config.target_url,
                "started_at": datetime.now(),
                "output_dir": temp_dir,
            }
        except FileNotFoundError:
            raise SQLMapNotFoundError(
                f"SQLMap calistirilamadi: {self.sqlmap_path}"
            )

        return task_id

    def get_scan_status(self, task_id: str) -> Dict[str, Any]:
        """
        Devam eden asenkron taramanin durumunu sorgular.
        
        Args:
            task_id: scan_async'den donen gorev kimligi.
            
        Returns:
            Durum sozlugu: {"status", "target_url", "elapsed_seconds", ...}
        """
        if task_id not in self._active_scans:
            return {
                "status": "not_found",
                "message": f"Gorev bulunamadi: {task_id}",
            }

        scan_info = self._active_scans[task_id]
        process = scan_info["process"]
        elapsed = (datetime.now() - scan_info["started_at"]).total_seconds()

        poll_result = process.poll()

        if poll_result is None:
            return {
                "status": ScanStatus.RUNNING,
                "task_id": task_id,
                "target_url": scan_info["target_url"],
                "elapsed_seconds": round(elapsed, 1),
            }
        else:
            return {
                "status": ScanStatus.COMPLETED,
                "task_id": task_id,
                "target_url": scan_info["target_url"],
                "elapsed_seconds": round(elapsed, 1),
                "return_code": poll_result,
            }

    def get_scan_result(self, task_id: str) -> Optional[ScanResult]:
        """
        Tamamlanmis asenkron taramanin sonuclarini alir.
        
        Args:
            task_id: Gorev kimligi.
            
        Returns:
            ScanResult veya None (tarama devam ediyorsa).
        """
        if task_id not in self._active_scans:
            return None

        scan_info = self._active_scans[task_id]
        process = scan_info["process"]

        if process.poll() is None:
            return None  # Henuz tamamlanmadi

        # Ciktiyi oku
        stdout, stderr = process.communicate()
        raw_output = stdout or ""
        if stderr:
            raw_output += "\n--- STDERR ---\n" + stderr

        # Parse et
        result = self.parser.parse_full_output(
            raw_output,
            config_dict=scan_info["config"],
        )
        result.target_url = scan_info["target_url"]
        result.started_at = scan_info["started_at"]
        result.finished_at = datetime.now()

        # Output dizininden ek sonuclari topla
        try:
            output_dir = scan_info.get("output_dir", "")
            if output_dir and os.path.isdir(output_dir):
                dir_result = self.parser.parse_target_results(output_dir)
                existing_titles = {v.title for v in result.vulnerabilities}
                for v in dir_result.vulnerabilities:
                    if v.title not in existing_titles:
                        result.vulnerabilities.append(v)
                self._cleanup_temp_dir(output_dir)
        except Exception:
            pass

        result.generate_summary()

        # Aktif taramalardan kaldir
        del self._active_scans[task_id]

        return result

    def stop_scan(self, task_id: str) -> bool:
        """
        Devam eden asenkron taramayi durdurur.
        
        Args:
            task_id: Durdurulacak gorev kimligi.
            
        Returns:
            True: Basariyla durduruldu. False: Gorev bulunamadi.
        """
        if task_id not in self._active_scans:
            return False

        scan_info = self._active_scans[task_id]
        process = scan_info["process"]

        try:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                logger.info("Tarama durduruldu [%s]", task_id)
        except Exception as e:
            logger.error("Tarama durdurulurken hata [%s]: %s", task_id, str(e))

        # Temizlik
        output_dir = scan_info.get("output_dir", "")
        if output_dir:
            self._cleanup_temp_dir(output_dir)

        del self._active_scans[task_id]
        return True

    def stop_all_scans(self):
        """Tum devam eden taramalari durdurur."""
        task_ids = list(self._active_scans.keys())
        for task_id in task_ids:
            self.stop_scan(task_id)
        logger.info("Tum taramalar durduruldu (%d adet)", len(task_ids))

    # ─────────────────────────────────────────────────────────────────────
    # Private Yardimcilar
    # ─────────────────────────────────────────────────────────────────────

    def _build_base_command(self) -> list:
        """SQLMap'i calistirmak icin temel komutu olusturur."""
        if not self.sqlmap_path:
            return ["sqlmap"]

        # "python3 -m sqlmap" gibi cok kelimeli komutlari bol
        if " " in self.sqlmap_path:
            return self.sqlmap_path.split()

        return [self.sqlmap_path]

    def _get_clean_env(self) -> dict:
        """Temiz cevre degiskenleri doner."""
        env = os.environ.copy()
        # SQLMap'in interaktif sorularini engellemek icin
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    @staticmethod
    def _cleanup_temp_dir(path: str):
        """Gecici dizini guvenli sekilde temizler."""
        try:
            if path and os.path.isdir(path) and "sqlmap_" in path:
                import shutil as _shutil
                _shutil.rmtree(path, ignore_errors=True)
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────
    # Context Manager Destegi
    # ─────────────────────────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_all_scans()
        return False

    def __str__(self) -> str:
        installed = "✅ Kurulu" if self.check_sqlmap_installed() else "❌ Kurulu degil"
        version = self.get_sqlmap_version() or "Bilinmiyor"
        active = len(self._active_scans)

        return (
            f"SQLMap Tarayici:\n"
            f"  Durum: {installed}\n"
            f"  Yol: {self.sqlmap_path or 'Bulunamadi'}\n"
            f"  Surum: {version}\n"
            f"  Aktif Taramalar: {active}"
        )
