#!/bin/bash
# Sızma Testi Otomasyon Aracı - Hızlı Kurulum ve Başlatma
# Geliştirici: Siber Savaşçılar Ekibi
# Kullanım: bash baslat.sh

set -e

echo "════════════════════════════════════════════════════════════"
echo "  🛡️  SIZMA TESTİ OTOMASYON ARACI — Hızlı Kurulum"
echo "════════════════════════════════════════════════════════════"
echo ""

# Python kontrolü
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 bulunamadı. Lütfen Python 3.9+ kurun."
    exit 1
fi

PY_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✓ Python $PY_VERSION bulundu"

# Sanal ortam
if [ ! -d "venv" ]; then
    echo "→ Sanal ortam oluşturuluyor..."
    python3 -m venv venv
fi
source venv/bin/activate
echo "✓ Sanal ortam aktif"

# Bağımlılıklar
echo "→ Bağımlılıklar kuruluyor..."
pip install --quiet -r requirements.txt 2>/dev/null || \
    pip install --quiet flask pyyaml requests urllib3
echo "✓ Bağımlılıklar hazır"

# Testler
echo "→ Testler çalıştırılıyor..."
if python -m pytest tests/ -q 2>&1 | tail -1 | grep -q "passed"; then
    echo "✓ Tüm testler geçti"
else
    echo "⚠ Bazı testler başarısız (pytest kurulu mu?)"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  KURULUM TAMAMLANDI"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Kullanım örnekleri:"
echo ""
echo "  # CLI ile tarama:"
echo "  python -m siber_savascilar http://testphp.vulnweb.com --quick"
echo ""
echo "  # Web arayüzü:"
echo "  python -m siber_savascilar.api.server"
echo "  # → http://localhost:5000"
echo ""
echo "  # Önceki taramaları listele:"
echo "  python -m siber_savascilar --list-scans"
echo ""
