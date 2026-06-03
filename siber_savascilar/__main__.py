"""
Paket olarak çalıştırma noktası.

Kullanım:
    python -m siber_savascilar <hedef-url>
"""

from .cli import main
import sys

sys.exit(main())
