# SQLMap Entegrasyon Modülü — Teknik Dokümantasyon

## 📖 Genel Bakış

Bu modül, **Siber Savaşçılar** projesi kapsamında SQL injection zafiyetlerini otomatik olarak tespit etmek için geliştirilmiştir. [SQLMap](https://sqlmap.org/) aracını Python subprocess aracılığıyla yöneterek, tarama başlatma, sonuç parse etme ve raporlama modülüne aktarma işlemlerini gerçekleştirir.

**Geliştiren:** Muhammet Sefa Kozan  
**Hafta:** 4 (30 Mart - 5 Nisan 2026)  
**Teknolojiler:** Python 3.8+, SQLMap, subprocess

---

## 🏗️ Mimari Yapı

```
src/
├── scanners/
│   └── sqlmap_scanner.py    → Ana tarama motoru (subprocess)
├── config/
│   └── sqlmap_config.py     → Yapilandirma sinifi
├── parsers/
│   └── sqlmap_parser.py     → Cikti ayristirici
├── models/
│   └── scan_result.py       → Veri modelleri
└── utils/
    └── validators.py        → Dogrulama araclari
```

### Veri Akış Diyagramı

```
Kullanici/UI  →  SQLMapConfig  →  SQLMapScanner  →  subprocess (sqlmap)
                                        ↓
                               SQLMapOutputParser  →  ScanResult
                                        ↓
                              Vulnerability [liste]
                                        ↓
                    ┌───────────────────┼──────────────────┐
                    ↓                   ↓                  ↓
              SCANS tablosu   VULNERABILITIES tablosu  REPORTS tablosu
```

---

## 🚀 Kullanım Kılavuzu

### Temel Kullanım

```python
from src.scanners.sqlmap_scanner import SQLMapScanner
from src.config.sqlmap_config import SQLMapConfig

# Scanner olustur
scanner = SQLMapScanner()

# Hizli tarama yapilandirmasi
config = SQLMapConfig.quick_scan(
    url="http://hedef-site.com/sayfa?id=1",
    dbms="mysql"
)

# Taramayi baslat
result = scanner.scan(config)

# Sonuclari kontrol et
if result.is_vulnerable:
    print(f"🔴 {result.vulnerability_count} zafiyet bulundu!")
    print(result.generate_summary())
else:
    print("✅ SQL injection zafiyeti tespit edilmedi.")
```

### Özel Yapılandırma ile Tarama

```python
config = SQLMapConfig(
    target_url="http://hedef-site.com/login",
    data="username=admin&password=test",    # POST verisi
    dbms="postgresql",                       # Veritabani turu
    level=3,                                 # Test derinligi (1-5)
    risk=2,                                  # Risk seviyesi (1-3)
    techniques="BEUST",                      # Istenen teknikler
    threads=5,                               # Es zamanli istek
    timeout=60,                              # Istek zaman asimi
    tamper=["space2comment", "randomcase"],   # WAF bypass
)

result = scanner.scan(config)
```

### Hazır Tarama Profilleri

| Profil | Level | Risk | Teknikler | Kullanım Alanı |
|--------|-------|------|-----------|----------------|
| `quick_scan()` | 1 | 1 | BE | Hızlı keşif, ilk tarama |
| `standard_scan()` | 3 | 2 | BEUST | Günlük taramalar |
| `deep_scan()` | 5 | 3 | BEUSTQ | Kapsamlı denetim |
| `post_scan()` | 3 | 2 | BEUST | Form/Login testleri |

```python
# Hizli kesif
config = SQLMapConfig.quick_scan("http://hedef.com?id=1")

# Standart tarama
config = SQLMapConfig.standard_scan("http://hedef.com?id=1", dbms="mysql")

# Derin analiz
config = SQLMapConfig.deep_scan("http://hedef.com?id=1")

# POST taramasi
config = SQLMapConfig.post_scan(
    "http://hedef.com/login",
    post_data="user=admin&pass=test"
)
```

---

## 📊 Raporlama Modülü Entegrasyonu

### Veritabanı Uyumlu Çıktı

Modül, Nursena'nın tasarladığı veritabanı şemasına tam uyumlu çıktı üretir:

```python
result = scanner.scan(config)
db_records = result.to_db_records()

# SCANS tablosuna ekleme
scan_data = db_records["scan"]
# → {"target_url": "...", "status": "completed", "started_at": "...", "finished_at": "..."}

# VULNERABILITIES tablosuna ekleme
for vuln in db_records["vulnerabilities"]:
    # → {"vuln_type": "SQLi", "severity": "Critical", "parameter": "id", ...}
    pass

# REPORTS tablosuna ekleme
report_data = db_records["report"]
# → {"summary": "🔴 ... hedefinde 4 adet SQL injection zafiyeti tespit edildi..."}
```

### JSON Rapor Çıktısı

```python
# Tam JSON rapor
json_report = result.to_json(indent=2)

# Raporlama modulune aktarma sozlugu
report_dict = result.to_report_dict()
```

---

## ⚙️ Yapılandırma Parametreleri Referansı

### Hedef Parametreleri

| Parametre | Tip | Varsayılan | Açıklama |
|-----------|-----|------------|----------|
| `target_url` | str | (zorunlu) | Hedef URL |
| `parameter` | str | "" | Test edilecek parametre(ler) |
| `data` | str | "" | POST verisi |
| `method` | str | "" | HTTP metodu (GET/POST) |
| `cookie` | str | "" | Cookie değeri |
| `headers` | dict | {} | Ek HTTP başlıkları |

### Veritabanı ve Test

| Parametre | Tip | Varsayılan | Açıklama |
|-----------|-----|------------|----------|
| `dbms` | str | "" | Hedef DBMS (otomatik tespit için boş bırakın) |
| `level` | int | 1 | Test seviyesi (1-5) |
| `risk` | int | 1 | Risk seviyesi (1-3) |
| `techniques` | str | "" | Injection teknikleri (BEUSTQ) |

### Desteklenen Veritabanı Sistemleri

MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, IBM DB2, Firebird, Sybase, SAP MaxDB, HSQLDB, H2, MonetDB, Apache Derby, Vertica, ve diğerleri.

### Injection Teknikleri

| Kod | Teknik | Risk | Açıklama |
|-----|--------|------|----------|
| B | Boolean-based blind | High | Mantıksal karşılaştırma ile veri sızdırma |
| E | Error-based | High | Hata mesajlarından veri çıkarma |
| U | Union query-based | Critical | UNION ile doğrudan veri çekme |
| S | Stacked queries | Critical | Birden fazla SQL komutu çalıştırma |
| T | Time-based blind | Medium | Zaman gecikmesi ile veri sızdırma |
| Q | Inline queries | Critical | Alt sorgu enjeksiyonu |

---

## 🧪 Testler

```bash
# Tum testleri calistir
pytest tests/ -v

# Belirli modul testi
pytest tests/test_sqlmap_config.py -v
pytest tests/test_sqlmap_parser.py -v
pytest tests/test_sqlmap_scanner.py -v
pytest tests/test_validators.py -v

# Coverage raporu
pytest tests/ --cov=src --cov-report=term-missing
```

---

## 🔒 Güvenlik Notları

1. **Parametre Sanitizasyonu**: Tüm kullanıcı girdileri `ConfigValidator.sanitize_parameter()` ile temizlenir (shell injection koruması).
2. **Batch Modu**: SQLMap varsayılan olarak `--batch` modunda çalışır (interaktif sorular otomatik yanıtlanır).
3. **Random User-Agent**: Her taramada rastgele tarayıcı kimliği kullanılır.
4. **Timeout Koruması**: Uzun süren taramalar otomatik olarak sonlandırılır.

> ⚠️ **Yasal Uyarı**: Bu araç yalnızca yasal izinleri alınmış sistemler üzerinde kullanılmalıdır.

---

## 📁 Dosya Özetleri

| Dosya | Satır | Açıklama |
|-------|-------|----------|
| `scan_result.py` | ~250 | Vulnerability ve ScanResult dataclass modelleri |
| `sqlmap_config.py` | ~320 | Yapılandırma, doğrulama ve komut dönüşümü |
| `sqlmap_parser.py` | ~310 | Regex tabanlı çıktı ayrıştırıcı |
| `sqlmap_scanner.py` | ~380 | Subprocess tabanlı tarama motoru |
| `validators.py` | ~240 | URL, DBMS ve güvenlik doğrulama |
