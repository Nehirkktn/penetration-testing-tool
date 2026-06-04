# SQLMap Entegrasyon Modülü — Teknik Detay

> **Siber Savaşçılar** | Fırat Üniversitesi – Yazılım Mühendisliği Temelleri Projesi  
> **Hazırlayan:** Muhammet Sefa Kozan | **Hafta:** 4 | **Son Teslim:** 9 Nisan 2026

> **Teknolojiler:** Python 3.8+, SQLMap, subprocess

---

## 📐 Proje Yapısı

```
src/
├── scanners/
│   └── sqlmap_scanner.py    → Ana tarama motoru
├── config/
│   └── sqlmap_config.py     → Yapilandirma sinifi
├── parsers/
│   └── sqlmap_parser.py     → Cikti ayristirici
├── models/
│   └── scan_result.py       → Veri modelleri
└── utils/
    └── validators.py        → Dogrulama araclari
```

---

## 1. `validators.py` — Girdi Doğrulama

Kullanıcıdan gelen tüm girdileri doğrular ve güvenli hale getirir.

### `URLValidator` sınıfı

| Metod | İşlev |
|-------|-------|
| `validate_url(url)` | http/https kontrolü, geçerli domain/IP doğrulaması |
| `has_parameters(url)` | URL'de `?id=1` gibi query parametresi var mı |
| `extract_parameters(url)` | Parametreleri çıkarır → `{"id": ["1"]}` |
| `validate_for_sqli_test(url)` | SQLi testi için uygunluk değerlendirmesi |

### `ConfigValidator` sınıfı

| Metod | İşlev |
|-------|-------|
| `validate_dbms(dbms)` | 28+ DBMS desteği, alias tanıma (`postgres` → `postgresql`) |
| `validate_techniques(techniques)` | BEUSTQ harflerinin geçerliliği |
| `validate_risk(risk)` | 1-3 aralık kontrolü |
| `validate_level(level)` | 1-5 aralık kontrolü |
| `sanitize_parameter(param)` | `;`, `\|`, `&` gibi tehlikeli karakterleri temizler (shell injection koruması) |

---

## 2. `sqlmap_config.py` — Yapılandırma Sınıfı

Tüm tarama parametrelerini toplar ve SQLMap komut satırı argümanlarına dönüştürür.

### `SQLMapConfig` (dataclass) alanları:

```python
target_url = "http://example.com/page?id=1"     # Hedef URL (zorunlu)
dbms       = "mysql"                            # Veritabani turu
level      = 3                                  # Test derinligi (1-5)
risk       = 2                                  # Risk seviyesi (1-3)
techniques = "BEUST"                            # Injection teknikleri
threads    = 3                                  # Es zamanli istek
batch      = True                               # Otomatik mod
```

### Komut dönüşüm mekanizması:

`to_command_args()` metodu her alanı SQLMap argümanına çevirir:

```python
config = SQLMapConfig(target_url="http://hedef.com?id=1", dbms="mysql", level=3)
print(config.to_command_args())
# ["-u", "http://hedef.com?id=1", "--dbms", "mysql", "--level", "3",
#  "--batch", "--random-agent"]
```

| Metod | Çıktı |
|-------|-------|
| `to_command_args()` | `["-u", "...", "--batch", "--level", "3"]` liste |
| `to_command_string()` | `sqlmap -u '...' --batch --level '3'` string |
| `validate()` | Hata listesi döner |
| `to_dict()` / `from_dict()` | JSON dönüşümü |

### Factory metodları:

```python
SQLMapConfig.quick_scan(url)       # Level 1, Risk 1, teknikler: BE
SQLMapConfig.standard_scan(url)    # Level 3, Risk 2, teknikler: BEUST
SQLMapConfig.deep_scan(url)        # Level 5, Risk 3, teknikler: BEUSTQ
SQLMapConfig.post_scan(url, data)  # POST form testi
```

---

## 3. `sqlmap_scanner.py` — Tarama Motoru

SQLMap'i `subprocess` ile komut satırında çalıştıran ana motor.

### SQLMap'i bulma süreci:

```python
scanner = SQLMapScanner()
# 1. PATH'te "sqlmap" arar
# 2. /usr/bin/sqlmap, /usr/local/bin/sqlmap kontrol eder
# 3. python3 -m sqlmap denemesi yapar
```

### Komut satırı çalıştırma mekanizması:

```python
# _run_scan() metodunun dahili calismasi:
cmd = self._build_base_command() + scan_config.to_command_args()
# Ornek: ["sqlmap", "-u", "http://hedef.com?id=1", "--batch", "--dbms", "mysql"]

process = subprocess.run(
    cmd,
    capture_output=True,    # stdout/stderr yakala
    text=True,              # String olarak al
    timeout=scan_timeout,   # Zaman asimi korumasi
)
# process.stdout → SQLMapParser'a gonderilir
```

### Tarama modları:

**Senkron:**
```python
result = scanner.scan(config)              # Bitene kadar bekler
result = scanner.scan(config, timeout=120) # Max 120 saniye
```

**Asenkron:**
```python
task_id = scanner.scan_async(config)       # Arka planda baslat
status = scanner.get_scan_status(task_id)  # Durumu sorgula
result = scanner.get_scan_result(task_id)  # Sonuclari al
scanner.stop_scan(task_id)                 # Durdur
```

### Hata yönetimi:

| Hata Sınıfı | Ne Zaman Fırlatılır |
|---|---|
| `SQLMapNotFoundError` | SQLMap sistemde bulunamadığında |
| `SQLMapScanError` | Tarama sırasında hata oluştuğunda |
| `TimeoutError` | Tarama zaman aşımına uğradığında |

---

## 4. `sqlmap_parser.py` — Çıktı Ayrıştırıcı

SQLMap'in konsol çıktısını regex ile okur ve `Vulnerability` nesnelerine dönüştürür.

### SQLMap çıktı örneği ve parse edilen veriler:

```
Parameter: id (GET)              → parametre="id", injection_type="GET"
    Type: boolean-based blind    → technique="boolean-based blind"
    Title: AND boolean-based ... → title="AND boolean-based ..."
    Payload: id=1 AND 5765=5765  → payload="id=1 AND 5765=5765"

back-end DBMS: MySQL >= 5.0     → dbms="MySQL", dbms_version=">=5.0"
```

### Teknik → Kritiklik eşlemesi:

| Teknik | Severity | Neden |
|--------|----------|-------|
| Union query | **Critical** | Doğrudan veri çekme |
| Stacked queries | **Critical** | Birden fazla SQL komutu |
| Inline query | **Critical** | Alt sorgu enjeksiyonu |
| Boolean-based | **High** | Veri sızdırma potansiyeli |
| Error-based | **High** | Hata mesajlarından veri çıkarma |
| Time-based | **Medium** | Yavaş ve sınırlı |

---

## 5. `scan_result.py` — Veri Modelleri

### `Vulnerability` sınıfı — Tek zafiyet:

```python
vuln = Vulnerability(
    vuln_type="SQLi",                       # Sabit
    severity="Critical",                    # Critical/High/Medium/Low
    parameter="id",                         # Zafiyetli parametre
    technique="Union query-based",          # Kullanilan teknik
    injection_type="GET",                   # GET/POST/Cookie/Header
    payload="id=1 UNION SELECT NULL,NULL",  # Kullanilan payload
    dbms="MySQL",                           # Tespit edilen DBMS
)
```

### `ScanResult` sınıfı — Tarama sonucu:

Hesaplanan özellikler:

| Özellik | Dönüş | Açıklama |
|---------|-------|----------|
| `is_vulnerable` | bool | Zafiyet var mı |
| `vulnerability_count` | int | Kaç zafiyet bulundu |
| `highest_severity` | str | En yüksek kritiklik |
| `affected_parameters` | list | Etkilenen parametreler |
| `duration_seconds` | float | Tarama süresi |

### Raporlama modülüne aktarım:

`to_db_records()` metodu Nursena'nın veritabanı şemasına uyumlu çıktı üretir:

```python
db_records = result.to_db_records()

db_records["scan"]
# → {"target_url": "...", "status": "completed", "started_at": "...", "finished_at": "..."}

db_records["vulnerabilities"]
# → [{"vuln_type": "SQLi", "severity": "Critical", "parameter": "id", ...}]

db_records["report"]
# → {"summary": "... hedefinde 3 adet SQL injection zafiyeti tespit edildi..."}
```

| Tablo | Eşlenen Alanlar |
|-------|----------------|
| `SCANS` | target_url, status, started_at, finished_at |
| `VULNERABILITIES` | vuln_type, severity, parameter, technique, payload |
| `REPORTS` | summary |

---

## 🧪 Test Sonuçları

```
test_sqlmap_config.py    — 25 test (yapilandirma, dogrulama, komut uretimi)
test_sqlmap_parser.py    — 25 test (cikti parse, severity, DBMS tespiti)
test_sqlmap_scanner.py   — 19 test (tarama, timeout, hata yonetimi, async)
test_validators.py       — 46 test (URL, DBMS, risk, level, sanitizasyon)
────────────────────────────────────
Toplam: 115 passed ✅
```
