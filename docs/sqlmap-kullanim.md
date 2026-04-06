# 🛡️ SQLMap Entegrasyon Modülü — Detaylı Kod Anlatımı

## Bu Proje Ne İşe Yarıyor?

Bu proje, **SQL Injection** (SQLi) zafiyetlerini otomatik olarak tespit etmek için geliştirilmiş bir Python modülüdür. Arka planda popüler bir siber güvenlik aracı olan **[SQLMap](https://sqlmap.org/)**'i kullanır. 

Kısacası: Bir web sitesine URL veriliyor, bu modül SQLMap aracını çalıştırıyor, çıktısını okuyor, zafiyetleri tespit edip raporluyor.

> **❗ Önemli:** Bu araç **"Siber Savaşçılar"** projesi kapsamında, Fırat Üniversitesi Yazılım Mühendisliği Temelleri dersi için geliştirilmiştir. Yalnızca **yasal izinli** sistemler üzerinde kullanılmalıdır.

---

## 📐 Proje Yapısı (Mimari)

```
sqlmap_module/
├── src/                          ← Ana kaynak kodlar
│   ├── __init__.py               ← Paket tanimi (v1.0.0)
│   ├── config/
│   │   └── sqlmap_config.py      ← Tarama ayarlari (URL, seviye, teknik vb.)
│   ├── models/
│   │   └── scan_result.py        ← Sonuc veri modelleri (Vulnerability, ScanResult)
│   ├── parsers/
│   │   └── sqlmap_parser.py      ← SQLMap ciktisini okuma ve anlama
│   ├── scanners/
│   │   └── sqlmap_scanner.py     ← SQLMap'i calistiran ana motor
│   └── utils/
│       └── validators.py         ← Girdi dogrulama (URL, DBMS, parametre)
├── tests/                        ← Birim testleri (115 test)
│   ├── test_sqlmap_config.py
│   ├── test_sqlmap_parser.py
│   ├── test_sqlmap_scanner.py
│   └── test_validators.py
├── docs/                         ← Teknik dokumantasyon
├── requirements.txt              ← Bagimliliklar
└── README.md                     ← Proje tanitimi
```

---

## 🔄 Veri Akışı — Sistem Nasıl Çalışıyor?

```
 Kullanıcı          SQLMapConfig        Validators        SQLMapScanner
 (URL girer)   →   (Ayarları topla)  →   (Doğrula)     →   (Çalıştır)
                                                               │
                                                               ▼
                                                           subprocess
                                                         (sqlmap komutu)
                                                               │
                                                               ▼
  Rapor /          ScanResult        SQLMapParser       SQLMap Çıktısı
  Veritabanı  ←  (Sonuç nesnesi)   ←  (Parse et)      ←   (Ham metin)
```

**Adım adım:**
1. Kullanıcı bir hedef URL ve tarama seçenekleri belirler
2. `SQLMapConfig` bu parametreleri `--batch --level=3 -u http://...` gibi komut satırı argümanlarına çevirir
3. `Validators` modülü URL'nin geçerli olduğunu, DBMS'in desteklendiğini doğrular
4. `SQLMapScanner` bu komutu `subprocess` ile terminalde çalıştırır
5. SQLMap'in ürettiği metin çıktısını `SQLMapParser` regex ile parse eder
6. Sonuçlar `Vulnerability` ve `ScanResult` nesnelerine dönüştürülür
7. Bu nesneler veritabanına (SCANS, VULNERABILITIES, REPORTS tabloları) veya JSON raporuna aktarılabilir

---

## 📁 Dosya Dosya Detaylı Açıklama

---

### 1. `src/utils/validators.py` — Girdi Doğrulama

> **Görev:** Kullanıcıdan gelen URL, DBMS, parametre gibi değerlerin güvenli ve geçerli olduğunu kontrol eder.

#### `URLValidator` sınıfı:
| Metod | Ne Yapar |
|-------|----------|
| `validate_url(url)` | URL'nin http/https olduğunu, geçerli domain/IP içerdiğini kontrol eder |
| `has_parameters(url)` | URL'de `?id=1` gibi query parametresi var mı bakar |
| `extract_parameters(url)` | URL'den parametreleri çıkarır → `{"id": ["1"]}` |
| `validate_for_sqli_test(url)` | URL'nin SQL injection testi için uygun olup olmadığını değerlendirir |

#### `ConfigValidator` sınıfı:
| Metod | Ne Yapar |
|-------|----------|
| `validate_dbms(dbms)` | "mysql", "postgresql" gibi DBMS'in desteklenip desteklenmediğini kontrol eder. "postgres" → "postgresql" gibi alias'ları da tanır |
| `validate_techniques(techniques)` | "BEU" gibi teknik harflerinin geçerli olup olmadığını bakar |
| `validate_risk(risk)` | Risk değerinin 1-3 arasında olduğunu doğrular |
| `validate_level(level)` | Level değerinin 1-5 arasında olduğunu doğrular |
| `sanitize_parameter(param)` | `;`, `\|`, `&` gibi shell injection'a yol açabilecek tehlikeli karakterleri temizler |

---

### 2. `src/config/sqlmap_config.py` — Yapılandırma Sınıfı

> **Görev:** SQLMap taraması için tüm parametreleri tek bir yerde toplar ve bunları SQLMap komut satırı argümanlarına dönüştürür.

#### `SQLMapConfig` sınıfı (dataclass):

**Temel alanlar:**
```python
target_url = "http://example.com/page?id=1"     # Hedef URL (zorunlu)
dbms       = "mysql"                            # Veritabani turu
level      = 3                                  # Test derinligi (1-5)
risk       = 2                                  # Risk seviyesi (1-3)
techniques = "BEUST"                            # Injection teknikleri
threads    = 3                                  # Es zamanli istek
batch      = True                               # Otomatik mod
```

**Önemli metodlar:**

| Metod | Ne Yapar |
|-------|----------|
| `validate()` | Tüm alanları kontrol eder, hata listesi döner |
| `to_command_args()` | `["-u", "http://...", "--batch", "--level", "3"]` gibi argüman listesi üretir |
| `to_command_string()` | Tam komut stringi döner: `sqlmap -u '...' --batch --level '3'` |
| `to_dict()` / `from_dict()` | JSON/dict dönüşümü |
| `copy()` | Derin kopya (orijinali değiştirmez) |

**Hazır profiller (Factory Methods):**
```python
SQLMapConfig.quick_scan(url)       # → Level 1, Risk 1, teknikler: BE, hizli
SQLMapConfig.standard_scan(url)    # → Level 3, Risk 2, teknikler: BEUST, dengeli
SQLMapConfig.deep_scan(url)        # → Level 5, Risk 3, teknikler: BEUSTQ, kapsamli
SQLMapConfig.post_scan(url, data)  # → POST form testi
```

---

### 3. `src/models/scan_result.py` — Veri Modelleri

> **Görev:** Bulunan zafiyetleri ve tarama sonuçlarını temsil eden yapılandırılmış veri sınıfları.

#### `Severity` sınıfı — Kritiklik seviyeleri:
```
Critical > High > Medium > Low > Informational
```

#### `Vulnerability` sınıfı — Tek bir zafiyet:
```python
vuln = Vulnerability(
    vuln_type="SQLi",                       # Her zaman "SQLi"
    severity="Critical",                    # Kritiklik seviyesi
    parameter="id",                         # Zafiyetli parametre
    technique="Union query-based",          # Kullanilan teknik
    injection_type="GET",                   # GET/POST/Cookie/Header
    payload="id=1 UNION SELECT NULL,NULL",  # SQLMap'in kullandigi payload
    dbms="MySQL",                           # Tespit edilen veritabani
    title="UNION query-based ...",          # SQLMap basligi
)
```

#### `ScanResult` sınıfı — Tam tarama sonucu:
```python
result = ScanResult(
    target_url="http://example.com?id=1",
    started_at=datetime.now(),
    finished_at=datetime.now(),
    status="completed",                       # pending/running/completed/error/timeout
    vulnerabilities=[vuln1, vuln2, ...],      # Bulunan zafiyetler
)

# Hesaplanan ozellikler:
result.is_vulnerable          # → True/False
result.vulnerability_count    # → 4
result.highest_severity       # → "Critical"
result.affected_parameters    # → ["id", "username"]
result.duration_seconds       # → 45.2
```

**Çıktı formatları:**
```python
result.generate_summary()   # → Turkce metin ozeti
result.to_json()             # → JSON formati
result.to_report_dict()      # → Raporlama modulune aktarilacak dict
result.to_db_records()       # → SCANS + VULNERABILITIES + REPORTS tablolarina uyumlu
```

---

### 4. `src/parsers/sqlmap_parser.py` — Çıktı Ayrıştırıcı

> **Görev:** SQLMap'in konsol çıktısını (metin) regex ile okuyarak yapılandırılmış `Vulnerability` nesnelerine dönüştürür.

**SQLMap şöyle bir çıktı verir:**
```
[INFO] testing 'AND boolean-based blind'
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5765=5765

    Type: union query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(...)--

back-end DBMS: MySQL >= 5.0
```

**Parser bu metni okur ve:**
- `Parameter: id (GET)` → parametre adı ve metodu çıkarır
- `Type: boolean-based blind` → teknik türünü çıkarır
- `Title: ...` → injection başlığını çıkarır
- `Payload: ...` → kullanılan payload'u çıkarır
- `back-end DBMS: MySQL >= 5.0` → veritabanı türü ve sürümünü çıkarır

**Teknik → Severity eşlemesi:**
| Teknik | Kritiklik | Neden |
|--------|-----------|-------|
| Union query | **Critical** | Doğrudan veri çekme |
| Stacked queries | **Critical** | Birden fazla SQL komutu |
| Inline query | **Critical** | Alt sorgu enjeksiyonu |
| Boolean-based | **High** | Veri sızdırma potansiyeli |
| Error-based | **High** | Hata mesajlarından veri çıkarma |
| Time-based | **Medium** | Daha yavaş ve sınırlı |

---

### 5. `src/scanners/sqlmap_scanner.py` — Ana Tarama Motoru

> **Görev:** SQLMap'i `subprocess` ile çalıştırır, sonuçları toplar.

#### `SQLMapScanner` sınıfı:

**Başlatma:**
```python
scanner = SQLMapScanner()
# Otomatik olarak:
# 1. PATH'te sqlmap arar
# 2. /usr/bin/sqlmap, /usr/local/bin/sqlmap gibi yaygin yollari kontrol eder
# 3. python3 -m sqlmap denemesi yapar
```

**Senkron tarama (bekleyerek):**
```python
result = scanner.scan(config)                  # Tarama bitene kadar bekler
result = scanner.scan(config, timeout=120)     # Max 120 saniye
```

**Asenkron tarama (arka planda):**
```python
task_id = scanner.scan_async(config)           # Arka planda baslat
status = scanner.get_scan_status(task_id)      # Durumu sorgula
result = scanner.get_scan_result(task_id)      # Sonuclari al
scanner.stop_scan(task_id)                     # Taramayi durdur
```

**Context manager desteği:**
```python
with SQLMapScanner() as scanner:
    result = scanner.scan(config)
# Blok bitince tum aktif taramalar otomatik durdurulur
```

---

## 🧪 Test Sonuçları

Tüm **115 test başarıyla geçiyor** ✅

```
tests/test_sqlmap_config.py    — 25 test (yapilandirma, dogrulama, komut uretimi, profiller)
tests/test_sqlmap_parser.py    — 25 test (cikti parse, severity, DBMS tespiti)
tests/test_sqlmap_scanner.py   — 19 test (tarama, timeout, hata yonetimi, async)
tests/test_validators.py       — 46 test (URL, DBMS, risk, level, sanitizasyon)
──────────────────────────────────────────
Toplam: 115 passed in 0.08s
```

---

## 🚀 Projeyi Nasıl Çalıştırırım?

### Adım 1: Gerekli Bağımlılıkları Kur

```bash
cd ~/Desktop/sqlmap_module
pip3 install -r requirements.txt
```

### Adım 2: SQLMap'i Kur (Henüz Kurulu Değilse)

```bash
# macOS:
brew install sqlmap

# Linux (Debian/Ubuntu):
sudo apt install sqlmap

# Veya pip ile:
pip3 install sqlmap
```

### Adım 3: Testleri Çalıştır (Doğrulama)

```bash
# Tum testler:
python3 -m pytest tests/ -v

# Coverage raporu ile:
python3 -m pytest tests/ --cov=src --cov-report=term-missing
```

### Adım 4: Modülü Python'da Kullan

```python
from src.scanners.sqlmap_scanner import SQLMapScanner
from src.config.sqlmap_config import SQLMapConfig

# 1) Scanner olustur
scanner = SQLMapScanner()

# 2) SQLMap kurulu mu kontrol et
if scanner.check_sqlmap_installed():
    print("SQLMap hazir!")
else:
    print("SQLMap bulunamadi. Once kurulum gerekli.")

# 3) Tarama yapilandirmasi olustur (izinli bir hedef URL)
config = SQLMapConfig.quick_scan(
    url="http://testphp.vulnweb.com/listproducts.php?cat=1",
    dbms="mysql"
)

# Yapilandirmayi goruntule
print(config)

# 4) Taramayi baslat
result = scanner.scan(config)

# 5) Sonuclari incele
print(f"Durum: {result.status}")
print(f"Zafiyet sayisi: {result.vulnerability_count}")
print(f"Sure: {result.duration_seconds} saniye")

if result.is_vulnerable:
    print(result.generate_summary())
    
    # Her bir zafiyet:
    for vuln in result.vulnerabilities:
        print(f"  [{vuln.severity}] {vuln.parameter} — {vuln.technique}")
    
    # JSON rapor:
    print(result.to_json())
    
    # Veritabanina aktarim:
    db_records = result.to_db_records()
```

> **⚠️ Uyarı:** `testphp.vulnweb.com` Acunetix'in test amaçlı sunduğu yasal bir zafiyet test sitesidir. Sadece bu tür **izinli** hedeflerde test yapın!

---

## ⚙️ Injection Teknikleri Referansı

| Harf | Teknik | Açıklama |
|------|--------|----------|
| **B** | Boolean-based blind | `AND 1=1` ile true/false farkını gözlemler |
| **E** | Error-based | Veritabanı hata mesajlarından veri çıkarır |
| **U** | Union query-based | `UNION SELECT` ile doğrudan veri çeker |
| **S** | Stacked queries | `;` ile ikinci SQL komutu enjekte eder |
| **T** | Time-based blind | `SLEEP(5)` ile gecikme farkını ölçer |
| **Q** | Inline queries | Alt sorgular ile veri sızdırır |

---

## 🗄️ Veritabanı Uyumu

Modül, Nursena'nın tasarladığı şu tablolara uyumlu çıktı üretir:

| Tablo | Eşlenen Alan | Kaynak |
|-------|-------------|--------|
| `SCANS` | target_url, status, started_at, finished_at | `ScanResult` |
| `VULNERABILITIES` | vuln_type, severity, parameter, technique, payload | `Vulnerability` |
| `REPORTS` | summary | `ScanResult.generate_summary()` |

```python
# Veritabanina kaydetme ornegi:
records = result.to_db_records()
# records["scan"]            → SCANS tablosuna
# records["vulnerabilities"] → VULNERABILITIES tablosuna
# records["report"]          → REPORTS tablosuna
```
