"""Tüm tarayıcı modülleri."""

from .base import BaseScanner
from .port_scanner import PortScanner
from .sqli_scanner import SQLiScanner
from .xss_scanner import XSSScanner
from .misconfig_scanner import MisconfigScanner
from .sensitive_data_scanner import SensitiveDataScanner
from .access_control_scanner import AccessControlScanner
from .scenario_scanner import ScenarioScanner
from .sqlmap_scanner import SQLMapScanner

__all__ = [
    "BaseScanner",
    "PortScanner",
    "SQLiScanner",
    "XSSScanner",
    "MisconfigScanner",
    "SensitiveDataScanner",
    "AccessControlScanner",
    "ScenarioScanner",
    "SQLMapScanner",
]


# Tarayıcı isim → sınıf eşlemesi (orkestratör için)
SCANNER_REGISTRY = {
    "ports": PortScanner,
    "sqli": SQLiScanner,
    "xss": XSSScanner,
    "misconfig": MisconfigScanner,
    "sensitive_data": SensitiveDataScanner,
    "access_control": AccessControlScanner,
    "scenarios": ScenarioScanner,
    "sqlmap": SQLMapScanner,
}
