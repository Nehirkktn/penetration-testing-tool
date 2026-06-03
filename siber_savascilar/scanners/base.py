"""
Tarayıcı Taban Sınıfı
======================

Tüm tarayıcı modüllerinin ortak arayüzü. Yeni bir tarayıcı eklemek için
bu sınıftan türetilir ve `scan()` metodu override edilir.
"""

from abc import ABC, abstractmethod
from typing import List
import logging

from ..core.models import Vulnerability


class BaseScanner(ABC):
    """
    Tüm tarayıcılar için temel arayüz.

    Subclass'lar `name`, `description` ve `scan()` tanımlamalıdır.
    """

    name: str = "base"
    description: str = "Soyut taban tarayıcı"

    def __init__(self, timeout: int = 5, verbose: bool = True):
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logging.getLogger(f"siber_savascilar.{self.name}")

    @abstractmethod
    def scan(self, target: str) -> List[Vulnerability]:
        """
        Hedefi tarar ve bulunan zafiyetleri döndürür.

        Args:
            target: Taranacak URL veya host

        Returns:
            Bulunan zafiyetlerin listesi (boş liste = temiz)
        """
        ...

    def log(self, message: str, level: str = "info"):
        """Sadece verbose modda yazdırır."""
        if self.verbose:
            getattr(self.logger, level)(message)
        # Verbose ya da değil, loglara yazılır
