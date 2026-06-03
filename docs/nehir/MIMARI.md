# Mimari Dokümanı

Bu dokümanda Sızma Testi Otomasyon Aracı projesinin mimari yapısı, bileşenleri ve
veri akışı açıklanmaktadır. Nehir Kökten'in `mimari_tasarım.md` dokümanındaki
3 katmanlı mimari temel alınmıştır.

## 1. Genel Yapı

Sistem 3 ana katmandan oluşur:

```
┌────────────────────────────────────────────────────────────────┐
│                      SUNUM KATMANI                              │
│  ┌──────────────────────┐    ┌──────────────────────────────┐  │
│  │   Komut Satırı (CLI) │    │   Web Arayüzü (Flask)        │  │
│  │   siber_savascilar/  │    │   siber_savascilar/api/      │  │
│  │   cli.py             │    │   + web/ (HTML/CSS/JS)       │  │
│  └──────────┬───────────┘    └──────────────┬───────────────┘  │
└─────────────┼───────────────────────────────┼──────────────────┘
              │                               │
              ▼                               ▼
┌────────────────────────────────────────────────────────────────┐
│                       İŞ KATMANI                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Orkestratör (orchestrator.py)               │  │
│  │  Modülleri sırayla çalıştırır, sonuçları toplar          │  │
│  └────┬─────────────────────────────────────────────────────┘  │
│       │                                                         │
│  ┌────▼────────────────────────────────────────────────────┐   │
│  │              Tarayıcı Modülleri (scanners/)             │   │
│  │  PortScanner  │ SQLiScanner   │ XSSScanner              │   │
│  │  MisconfigScanner │ SensitiveDataScanner                │   │
│  │  AccessControlScanner │ ScenarioScanner │ SQLMapScanner │   │
│  └────┬────────────────────────────────────────────────────┘   │
│       │                                                         │
│  ┌────▼────────────────────────────────────────────────────┐   │
│  │              Raporlama (reporting/)                     │   │
│  │  ReportGenerator → HTML / JSON / PDF                    │   │
│  └─────────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────────────┐
│                       VERİ KATMANI                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              SQLite Veritabanı (core/database.py)        │  │
│  │  USERS │ SCAN_CONFIGS │ SCANS │ VULNERABILITIES │ REPORTS│  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## 2. Modüller ve Sorumluluklar

### Sunum Katmanı (Presentation Layer)

#### CLI Arayüzü — `cli.py`
- argparse tabanlı komut satırı
- Çalıştırma: `python -m siber_savascilar <hedef-url>`
- Modül seçimi, hızlı tarama, rapor formatları için bayraklar
- Eski taramaları listeler

#### Web Arayüzü — `api/server.py` + `web/`
- Flask backend
- REST API endpoint'leri (JSON)
- Şevval Duran'ın frontend tasarımı (Dashboard, Yeni Tarama, Raporlar, Senaryolar)
- Statik dosya servisi

### İş Katmanı (Business Layer)

#### Orkestratör — `orchestrator.py`
Tarama akışının kalbi. Sorumlulukları:
1. URL'yi normalize edip doğrular
2. DB'de yeni bir tarama kaydı oluşturur
3. Seçilen tarayıcı modüllerini sırayla çalıştırır
4. Her modülün bulgularını `ScanResult`'a toplar
5. Tarama bitince DB'ye yazar
6. İlerleme callback'i destekler (web UI için)

#### Tarayıcılar — `scanners/`
Her tarayıcı `BaseScanner` soyut sınıfından türer ve `scan(target)` metodunu
implement eder. Tüm tarayıcılar `Vulnerability` listesi döndürür.

Tarayıcı listesi:
| Modül | OWASP | Kaynak |
|---|---|---|
| port_scanner | — | Nursena, hardcoded path bug'ı düzeltilmiş |
| sqli_scanner | A03 | Nursena, pattern listesi genişletilmiş |
| xss_scanner | A03 | Nursena, payload seti genişletilmiş |
| misconfig_scanner | A05 | Nursena |
| sensitive_data_scanner | A02 | Nursena, regex pattern'leri eklendi |
| access_control_scanner | A01 | Nursena |
| scenario_scanner | — | Muhammed'in YAML motoru |
| sqlmap_scanner | A03 | Sefa'nın kodundan basit wrapper |

#### Raporlama — `reporting/generator.py`
- HTML: gömülü CSS ile interaktif rapor
- JSON: SIEM ve dış sistemlere entegrasyon için
- PDF: reportlab varsa otomatik (Nehir'in rapor şablonu)

### Veri Katmanı (Data Layer)

#### Veritabanı — `core/database.py`
SQLite (5 tablo, Nursena'nın orijinal şeması):
- `users` — kullanıcı hesapları
- `scan_configs` — kullanıcıların kayıtlı tarama yapılandırmaları
- `scans` — her tarama oturumu
- `vulnerabilities` — bulunan zafiyetler (scan_id ile ilişkili)
- `reports` — özet, HTML/JSON dosya yolları

CASCADE delete: bir tarama silinince zafiyetleri ve raporu da silinir.

Foreign keys etkinleştirilmiş. Connection context manager
(`with db.connection() as conn:`) ile otomatik commit/rollback.

## 3. Veri Modelleri

### Vulnerability
Tek bir güvenlik açığını temsil eder. Tüm tarayıcılar bu yapıyı döndürür.

```python
Vulnerability(
    vuln_type="SQL Injection",
    severity="Critical",
    target="http://example.com/?id=1",
    description="...",
    payload="' OR 1=1--",
    evidence="MySQL hata mesajı tespit edildi",
    cwe="CWE-89",
    remediation="Parametreli sorgular kullanın",
    details={"dbms": "MySQL"}
)
```

### ScanResult
Bir tarama oturumunun tüm sonuçlarını taşır. Hesaplanmış özelliklere sahiptir
(severity_breakdown, highest_severity, duration_seconds vb.).

## 4. Genişletme Noktaları

### Yeni Tarayıcı Eklemek
1. `siber_savascilar/scanners/yeni_scanner.py` oluştur
2. `BaseScanner`'dan türet, `scan(target)` metodunu yaz
3. `siber_savascilar/scanners/__init__.py`'deki `SCANNER_REGISTRY`'ye ekle

### Yeni YAML Senaryo Eklemek
`scenarios_data/` klasörüne `.yaml` dosyası ekle. Otomatik yüklenir.

### Yeni Rapor Formatı Eklemek
`ReportGenerator` sınıfına `generate_<format>` metodu ekle, CLI'da bayrağı tanımla.

## 5. Güvenlik Notları

- **SSRF koruması:** `URLValidator.validate(url, allow_internal=False)` ile
  dahili IP aralıkları (192.168.*, 10.*, 127.*) reddedilir.
- **CRLF injection koruması:** Kontrol karakterleri içeren URL'ler reddedilir.
- **SQL injection (kendi DB'mizde):** Tüm sorgular parametreli (`?` placeholder).
- **XSS (HTML rapor):** Kullanıcı girdilerinden gelen veriler `_escape()` ile
  HTML-encode edilir.
- **SQLMap argument injection:** Subprocess çağrısında sadece sabit komut
  satırı bayrakları kullanılır.
