# 🛡️ Sızma Testi Otomasyon Aracı

**OWASP Top 10 (2021) referanslı sızma testi otomasyon aracı.**

Fırat Üniversitesi Yazılım Mühendisliği Temelleri dersi dönem projesi.
Geliştirici ekibi: **Siber Savaşçılar**.

---

## Özellikler

- **8 farklı tarama modülü:** Port tarama, SQL Injection, XSS, yapılandırma
  hataları, hassas veri sızıntısı, bozuk erişim kontrolü, özelleştirilebilir
  YAML senaryoları, SQLMap entegrasyonu.
- **İki kullanım modu:** Komut satırı (CLI) ve web paneli.
- **3 rapor formatı:** HTML (görsel), JSON (entegrasyon), PDF (opsiyonel).
- **SQLite veritabanı:** Tüm taramalar ve bulgular kalıcı olarak saklanır.
- **OWASP Top 10 2021 kapsamı:** A01 (Broken Access), A02 (Crypto Failures),
  A03 (Injection), A05 (Misconfiguration).
- **Akıllı timeout yönetimi:** Reachability ön kontrolü + üst üste hata
  durumunda erken kesme (ulaşılamaz hedeflerde 5-60sn'de tamamlanır).
- **394 birim test:** Tüm modüller mock-server ve parametrize edilmiş
  testlerle doğrulanmıştır.
- **Türkçe-dostu UI:** Tooltip'li modül seçimi, OWASP rozetleri.

---

## Kurulum

### 🐳 Docker ile (Önerilen — En Kolay Yöntem)

Sadece **Docker** ve **Docker Compose** kuruluysa tek komut yeterli:

```bash
docker compose up
```

İlk seferde 2-3 dakika sürer (Python imajı, Nmap, SQLMap ve Python paketleri
indirilir). Bittiğinde tarayıcıdan açın:

```
http://localhost:5000
```

**Durdurmak için:** `Ctrl+C` veya başka bir terminalde `docker compose down`

**Avantajları:**
- Python sürümü ve sistem farkı gözetmeksizin her bilgisayarda aynı çalışır
- Nmap ve SQLMap önceden kurulu gelir
- Veritabanı ve raporlar `./data` ve `./reports` klasörlerinde kalıcı olarak saklanır

**Docker yoksa:** https://www.docker.com/products/docker-desktop adresinden
Docker Desktop'ı indir, kur ve aç.

---

### 🐍 Manuel kurulum (Docker olmadan)

### 1. Bağımlılıkları yükleyin

```bash
# Sanal ortam (önerilen)
python -m venv venv
source venv/bin/activate     # Linux/Mac
# venv\Scripts\activate      # Windows

# Bağımlılıklar
pip install -r requirements.txt
```

### 2. (Opsiyonel) Nmap kurulumu

Daha iyi port tarama için sistemde `nmap` binary'si olmalı:

```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Windows: https://nmap.org/download.html
```

Nmap kurulu değilse otomatik olarak Python socket fallback'i çalışır.

### 3. (Opsiyonel) SQLMap

Gelişmiş SQL injection testleri için:

```bash
sudo apt install sqlmap
```

---

## Kullanım

### Komut satırı

```bash
# Varsayılan: tüm modüller
python -m siber_savascilar http://testphp.vulnweb.com

# Sadece belirli modüller
python -m siber_savascilar http://example.com --modules sqli xss misconfig

# Hızlı tarama (sqli + xss + misconfig)
python -m siber_savascilar http://example.com --quick

# PDF rapor da üret
python -m siber_savascilar http://example.com --pdf

# Önceki taramaları listele
python -m siber_savascilar --list-scans
```

### Web paneli

```bash
python -m siber_savascilar.api.server
```

Sonra tarayıcıdan: `http://localhost:5000`

Web panelden:
- Dashboard üzerinden istatistikleri ve son taramaları görün
- "Yeni Tarama" sekmesinden hedef ve modül seçerek tarama başlatın
- "Raporlar" sekmesinden HTML raporlara erişin
- "Test Senaryoları" sekmesinden yüklü YAML şablonlarını listeleyin

---

## Proje Yapısı

```
siber-savascilar/
├── siber_savascilar/         # Ana paket
│   ├── core/                 # Veri modelleri, DB, validatorlar
│   ├── scanners/             # Tarayıcı modülleri (8 adet)
│   ├── reporting/            # HTML/JSON/PDF rapor üretici
│   ├── api/                  # Flask backend
│   ├── orchestrator.py       # Tarama orkestratörü
│   └── cli.py                # Komut satırı arayüzü
├── web/                      # Frontend (HTML/CSS/JS)
├── scenarios_data/           # YAML senaryo dosyaları
├── tests/                    # Pytest test paketi
├── data/                     # SQLite DB (otomatik oluşur)
├── reports/                  # Üretilen raporlar
├── docs/                     # Proje dokümantasyonu
├── requirements.txt
└── setup.py
```

---

## YAML Senaryo Yazma

`scenarios_data/` klasörüne kendi `.yaml` dosyalarınızı ekleyebilirsiniz.

Format:

```yaml
id: my-custom-test
info:
  name: "Test adı"
  author: "yazar"
  severity: "High"
  description: "Ne yapıyor?"
  cwe: "CWE-XXX"
  remediation: "Nasıl çözülür?"

requests:
  - method: GET
    path:
      - "{{target_url}}/test-path"
    matchers-condition: and    # veya "or"
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["beklenen kelime"]
      - type: regex
        regex: ["pattern1", "pattern2"]
      - type: header
        headers:
          X-Powered-By: "PHP/5.6"
```

3 örnek için `scenarios_data/` klasörüne bakın.

---

## Testler

```bash
# Tüm testleri çalıştır (394 test)
pytest tests/

# Sadece bir modül
pytest tests/test_models.py -v

# Verbose detay
pytest tests/ -v
```

Test paketi 394 birim test içerir:
- Veri modelleri (Severity, Vulnerability, ScanResult)
- URL validatör (SSRF, CRLF, normalize)
- Veritabanı (CRUD, schema, foreign keys)
- 8 tarayıcı modülünün her biri (yerel mock-server ile)
- Orkestratör (reachability, akış, modül seçimi)
- Rapor üretici (HTML/JSON/PDF)
- Flask API endpoint'leri
- YAML senaryo motoru

---

## Ekip

| Rol | İsim | Sorumluluk |
|---|---|---|
| Proje Yöneticisi | Nehir Kökten | Mimari, gereksinim analizi, raporlama planı |
| Yazılım Mühendisi | Nursena Karaduman | Tarama motoru çekirdeği, veritabanı, OWASP analizi |
| Yazılım Mühendisi | Muhammed B. Başbay | YAML senaryo motoru, teknoloji araştırması |
| Yazılım Mühendisi | Şevval Duran | Frontend, UI/UX, geliştirme ortamı |
| Yazılım Mühendisi | M. Sefa Kozan | SQLMap entegrasyonu, test altyapısı, güvenlik validasyonu |

---

## Lisans

Bu proje akademik amaçla geliştirilmiştir. Sadece sahip olduğunuz veya açıkça
test izniniz olan sistemlerde kullanın. Yetkisiz sistemleri taramak yasal
suçtur.

## Dokümantasyon

- `README.md` — Bu dosya (genel bakış ve kullanım)
- `docs/KURULUM.md` — Detaylı kurulum rehberi
- `docs/MIMARI.md` — Sistem mimarisi ve modüller
- `docs/GOREV_DURUMU.md` — Trello görev haritalaması ve final teslim durumu
