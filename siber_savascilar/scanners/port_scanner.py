"""
Port Tarayıcı (Nmap Entegrasyonu)
==================================

Nursena Karaduman'ın port_scanner.py modülünden adapte edildi.

Düzeltilen Buglar:
    BUG-001 (Nursena'nın bug raporundan): Hard-coded Windows Nmap yolu kaldırıldı.
            Şimdi PATH'ten otomatik bulunur, opsiyonel olarak özelleştirilebilir.

İki çalışma modu:
    1. python-nmap kütüphanesi varsa onu kullanır (zengin sonuç)
    2. Yoksa Python'un kendi socket modülüyle hızlı bir TCP connect taraması yapar
       (fallback — Nmap kurulumu zorunlu değil)
"""

import socket
import shutil
import platform
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseScanner
from ..core.models import Vulnerability, Severity, VulnType
from ..core.validators import TargetValidator


# Yaygın port → servis eşlemesi
COMMON_PORTS = {
    21: ("FTP", Severity.MEDIUM),
    22: ("SSH", Severity.LOW),
    23: ("Telnet", Severity.HIGH),  # Telnet şifresiz, kritik
    25: ("SMTP", Severity.LOW),
    53: ("DNS", Severity.LOW),
    80: ("HTTP", Severity.INFO),
    110: ("POP3", Severity.LOW),
    143: ("IMAP", Severity.LOW),
    443: ("HTTPS", Severity.INFO),
    445: ("SMB", Severity.HIGH),  # SMB genelde açık olmamalı
    3306: ("MySQL", Severity.HIGH),  # DB internet'e açıksa kritik
    3389: ("RDP", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    5900: ("VNC", Severity.HIGH),
    6379: ("Redis", Severity.CRITICAL),  # Default Redis = auth yok
    8080: ("HTTP-Alt", Severity.INFO),
    8443: ("HTTPS-Alt", Severity.INFO),
    9200: ("Elasticsearch", Severity.CRITICAL),
    27017: ("MongoDB", Severity.CRITICAL),
}


class PortScanner(BaseScanner):
    """Port tarama — nmap veya socket fallback."""

    name = "port_scanner"
    description = "Nmap (varsa) veya socket ile TCP port tarama"

    def __init__(self, ports: List[int] = None, timeout: int = 3,
                 max_workers: int = 50, verbose: bool = True):
        super().__init__(timeout=timeout, verbose=verbose)
        self.ports = ports or list(COMMON_PORTS.keys())
        self.max_workers = max_workers
        self._has_nmap = self._check_nmap()

    def _check_nmap(self) -> bool:
        """Sistemde nmap binary'si var mı kontrol et."""
        nmap_path = shutil.which("nmap")
        if nmap_path:
            self.log(f"nmap bulundu: {nmap_path}")
            return True

        # Windows'ta varsayılan kurulum yolları
        if platform.system() == "Windows":
            import os
            for path in [r"C:\Program Files\Nmap", r"C:\Program Files (x86)\Nmap"]:
                if os.path.isdir(path):
                    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + path
                    if shutil.which("nmap"):
                        self.log(f"nmap PATH'e eklendi: {path}")
                        return True

        self.log("nmap binary'si bulunamadı, socket fallback kullanılacak", "warning")
        return False

    def scan(self, target: str) -> List[Vulnerability]:
        """Hedef üzerinde port tarama yapar."""
        host = TargetValidator.extract_host(target)

        if not TargetValidator.is_valid_target(host):
            self.log(f"Geçersiz hedef: {host}", "error")
            return []

        self.log(f"Port taraması başlıyor: {host}")

        if self._has_nmap:
            open_ports = self._scan_with_nmap(host)
        else:
            open_ports = self._scan_with_socket(host)

        return self._ports_to_vulnerabilities(host, open_ports)

    def _scan_with_socket(self, host: str) -> List[Tuple[int, str]]:
        """Socket-tabanlı paralel TCP connect taraması (fallback)."""
        open_ports = []

        def check_port(port: int):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        return port
            except (socket.gaierror, socket.timeout, OSError):
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_port, p): p for p in self.ports}
            for fut in as_completed(futures):
                port = fut.result()
                if port is not None:
                    service_name = COMMON_PORTS.get(port, ("unknown", Severity.INFO))[0]
                    open_ports.append((port, service_name))
                    self.log(f"  AÇIK: {port}/tcp ({service_name})")

        return sorted(open_ports)

    def _scan_with_nmap(self, host: str) -> List[Tuple[int, str]]:
        """python-nmap kütüphanesini kullanır (varsa)."""
        try:
            import nmap
        except ImportError:
            self.log("python-nmap kütüphanesi yok, socket'e dönülüyor", "warning")
            return self._scan_with_socket(host)

        scanner = nmap.PortScanner()
        port_str = ",".join(map(str, self.ports))
        scanner.scan(host, port_str, "-T4 --open")

        open_ports = []
        for h in scanner.all_hosts():
            for port in scanner[h].get("tcp", {}):
                info = scanner[h]["tcp"][port]
                if info["state"] == "open":
                    service = info.get("name") or COMMON_PORTS.get(port, ("unknown",))[0]
                    open_ports.append((port, service))
                    self.log(f"  AÇIK: {port}/tcp ({service})")

        return sorted(open_ports)

    def _ports_to_vulnerabilities(self, host: str,
                                  open_ports: List[Tuple[int, str]]) -> List[Vulnerability]:
        """Açık portları zafiyet listesine çevirir."""
        vulns = []
        for port, service in open_ports:
            _, severity = COMMON_PORTS.get(port, (service, Severity.INFO))

            # INFO seviyesi 80/443 gibi normal portlar için
            if severity == Severity.INFO:
                continue

            vulns.append(Vulnerability(
                vuln_type=VulnType.OPEN_PORT,
                severity=severity,
                target=f"{host}:{port}",
                description=f"Port {port} ({service}) dış erişime açık",
                evidence=f"TCP {port} → open",
                cwe="CWE-200",
                remediation=self._remediation_for_port(port, service),
                details={"port": port, "service": service},
            ))
        return vulns

    @staticmethod
    def _remediation_for_port(port: int, service: str) -> str:
        suggestions = {
            23: "Telnet şifresizdir. SSH (port 22) ile değiştirin.",
            445: "SMB internet'e açık olmamalı. Firewall ile kapatın.",
            3306: "MySQL internet'e açık olmamalı. Bind-address localhost yapın.",
            3389: "RDP saldırı yüzeyini büyütür. VPN arkasına alın.",
            5432: "PostgreSQL listen_addresses sadece localhost olmalı.",
            6379: "Redis varsayılan olarak şifresizdir. requirepass ekleyin.",
            27017: "MongoDB --auth ile çalıştırılmalı.",
            9200: "Elasticsearch için xpack.security.enabled=true yapın.",
        }
        return suggestions.get(port, f"{service} servisinin gerçekten dışarıya açık "
                                     f"olması gerekli mi gözden geçirin.")
