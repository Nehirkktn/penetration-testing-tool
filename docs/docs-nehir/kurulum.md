# Kurulum Rehberi

## Sistem Gereksinimleri

- **Python:** 3.9 veya üstü (manuel kurulum için)
- **İşletim Sistemi:** Linux, macOS veya Windows
- **Disk:** ~50 MB (Docker ile ~500 MB)
- **RAM:** Minimum 256 MB

---

## 🐳 KOLAY YOL: Docker ile Kurulum

Docker kurulu ise tüm sistem **tek komutla** ayağa kalkar.

### Ön koşul: Docker Desktop kurulu olmalı

- **Windows / macOS:** https://www.docker.com/products/docker-desktop indir, kur, çalıştır
- **Linux (Ubuntu):**
  ```bash
  sudo apt install docker.io docker-compose-plugin
  ```

### Çalıştırma

```bash
# Proje klasöründe
docker compose up
```

İlk seferde 2-3 dakika kurulum yapar. Sonra:

```
http://localhost:5000
```

adresinden arayüze ulaşırsınız.

### Faydalı Docker komutları

```bash
docker compose up -d              # Arka planda çalıştır
docker compose logs -f            # Logları canlı izle
docker compose down               # Durdur ve konteyneri sil
docker compose restart            # Yeniden başlat
docker compose build --no-cache   # Sıfırdan yeniden inşa et
```

### Avantajları
- Nmap ve SQLMap zaten kurulu gelir (port tarama + SQL injection için kritik)
- Python sürümü uyumsuzluğu sorunu yok
- `./data` ve `./reports` klasörleri host makinede kalıcı kalır
- Konteyner kapansa bile veritabanı ve raporlar kaybolmaz

---

## 🐍 ALTERNATİF YOL: Manuel Kurulum (Docker Olmadan)

## Adım 1: Projeyi İndirin

```bash
# Zip dosyasını açın veya git ile klonlayın
unzip siber-savascilar-final.zip
cd siber-savascilar
```

## Adım 2: Sanal Ortam (Önerilen)

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

## Adım 3: Bağımlılıkları Kurun

### Minimum kurulum (sadece zorunlu paketler)

```bash
pip install flask pyyaml requests urllib3
```

### Tam kurulum (önerilen)

```bash
pip install -r requirements.txt
```

Tam kurulum şunları da içerir:
- `python-nmap` — Daha iyi port tarama
- `reportlab` — PDF rapor üretimi
- `pytest` — Test koşumu

### Geliştirilebilir kurulum

```bash
pip install -e .
```

Bu şekilde kurulduğunda:
- `siber-savascilar <hedef>` komutu doğrudan kullanılabilir
- `siber-savascilar-web` ile web sunucu başlatılabilir

## Adım 4: (Opsiyonel) Nmap Kurulumu

Nmap kurulu değilse Python socket fallback'i otomatik çalışır, ama Nmap
daha hızlı ve detaylıdır.

### Ubuntu / Debian
```bash
sudo apt update && sudo apt install nmap
```

### macOS (Homebrew)
```bash
brew install nmap
```

### Windows
https://nmap.org/download.html adresinden indirin ve kurun. Kurulum sonrası
"C:\Program Files\Nmap" PATH'e otomatik tanınmazsa, ortam değişkenine
manuel ekleyin.

## Adım 5: (Opsiyonel) SQLMap Kurulumu

Gelişmiş SQLi testleri için:

```bash
# Ubuntu / Debian
sudo apt install sqlmap

# macOS
brew install sqlmap

# Windows (Python ile)
pip install sqlmap
```

## Adım 6: Doğrulama

### Test paketini çalıştırın

```bash
python -m pytest tests/
```

Beklenen çıktı: `25 passed`

### Bir test taraması yapın

```bash
python -m siber_savascilar http://testphp.vulnweb.com --quick
```

`reports/` klasöründe `rapor_1_...html` ve `rapor_1_...json` dosyalarının
oluşması gerekir.

### Web arayüzünü başlatın

```bash
python -m siber_savascilar.api.server
```

Tarayıcıdan `http://localhost:5000` adresini açın.

## Olası Sorunlar

### `ModuleNotFoundError: No module named 'siber_savascilar'`

Çözüm: Komutları proje kök dizininden çalıştırın (siber-savascilar/),
veya `pip install -e .` ile kurun.

### Nmap port scanner hata veriyor

Çözüm: Nmap kurulu değilse otomatik olarak socket fallback kullanılır.
İsterseniz `--modules` ile portları hariç tutabilirsiniz:

```bash
python -m siber_savascilar http://example.com \
  --modules sqli xss misconfig sensitive_data
```

### PDF üretilmiyor

Çözüm: `pip install reportlab` ile kurun, sonra `--pdf` bayrağıyla çalıştırın.

### Web arayüzü açılmıyor

Çözüm: Port 5000 başka bir uygulama tarafından kullanılıyor olabilir.
Sunucuyu farklı portta başlatın:

```python
from siber_savascilar.api.server import run
run(port=8080)
```

## Geliştirme Ortamı

Şevval Duran'ın `geliştirme_ortami.docx` dokümanından adaptasyon:

### Önerilen Editörler
- **PyCharm** — Tam IDE deneyimi
- **VS Code** — Python eklentisiyle
- **Sublime Text** — Hafif alternatif

### Önerilen VS Code Eklentileri
- Python (Microsoft)
- Pylance
- Python Test Explorer
- GitLens

### Kod Stili
- PEP 8'e uyun
- Türkçe yorumlar tercih edilir (ekip içi tutarlılık)
- Docstring'ler tüm public fonksiyonlarda zorunludur
