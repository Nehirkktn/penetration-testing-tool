# Nursena Karaduman — Görev Dosyaları (Yazılım Mühendisi)

Bu klasördeki dosyalar, sana atanan görevlere karşılık gelen proje parçalarıdır.
Branch adın: `feature/nursena-karaduman`

---

## Görev 1 — Proje Kapsamı Analizi
**İlgili Dosya:** `siber_savascilar/core/models.py`

Projenin odaklandığı siber güvenlik tehditleri `VulnType` sınıfında tanımlanmıştır:
- `SQL Injection` (A03:2021), `XSS` (A03:2021), `Broken Access Control` (A01:2021),
  `Security Misconfiguration` (A05:2021), `Sensitive Data Exposure` (A02:2021),
  `Open Port / Service Exposure`, `Custom Scenario Match`, `IDOR`
- OWASP Top 10 (2021) kapsamı esas alınmıştır.

---

## Görev 2 — Zafiyet Tarama Motoru Gereksinimleri Analizi
**İlgili Dosyalar:**
- `siber_savascilar/core/models.py` → `Severity`, `ScanStatus`, `VulnType`, `Vulnerability`, `ScanResult` sınıfları
- `siber_savascilar/core/validators.py` → URL/host doğrulama, SSRF koruması

Tarama motorunun desteklediği protokoller, veri tipleri, performans yapısı
ve OWASP zafiyet listesi bu modeller üzerinden tanımlanmıştır.

---

## Görev 3 — Zafiyet Tarama Modüllerinin Tasarımı
**İlgili Dosyalar:**
- `siber_savascilar/scanners/base.py` → `BaseScanner` soyut sınıfı (ortak arayüz)
- `siber_savascilar/scanners/__init__.py` → `SCANNER_REGISTRY` (isim → sınıf eşlemesi)

Modüler mimari: her tarayıcı `BaseScanner`'dan türer, `scan(target) -> List[Vulnerability]`
metodunu implement eder. Modüller arası iletişim `ScanResult` aracılığıyla sağlanır.

---

## Görev 4 — Nmap & Temel Zafiyet Tarama Fonksiyonları
**İlgili Dosyalar:**
- `siber_savascilar/scanners/port_scanner.py` → Nmap entegrasyonu + socket fallback
- `siber_savascilar/scanners/sqli_scanner.py` → SQL Injection tespiti
- `siber_savascilar/scanners/xss_scanner.py` → XSS tespiti
- `tests/test_scanners.py`

Port tarayıcı:
- `python-nmap` kütüphanesi varsa kullanır; yoksa Python `socket` modülüyle fallback yapar
- 20+ yaygın port tarar (FTP, SSH, HTTP, HTTPS, MySQL, PostgreSQL, ...)

SQL Injection tarayıcı: URL parametrelerine otomatik payload enjeksiyonu,
DBMS imzası pattern eşleştirme, time-based blind SQLi testi.

XSS tarayıcı: HTML / attribute / SVG / JS context için farklı payload setleri.

---

## Görev 5 — Sızma Testi Senaryoları (SQL Injection & XSS)
**İlgili Dosyalar:**
- `siber_savascilar/scanners/access_control_scanner.py` → OWASP A01: admin panel, IDOR
- `siber_savascilar/scanners/misconfig_scanner.py` → OWASP A05: açık dizin, hassas dosya, güvenlik başlıkları
- `siber_savascilar/scanners/sensitive_data_scanner.py` → OWASP A02: API key, AWS key, JWT, e-posta sızıntısı

---

## Görev 6 — Test Senaryoları Tamamlama & Bug Raporları
**İlgili Dosyalar:**
- `tests/test_scanners.py` → tarayıcı modülleri entegrasyon testleri (canlı HTTP sunucu)
- `tests/test_models.py` → veri modeli testleri
- `tests/test_database.py` → veritabanı işlemleri
- `tests/test_database_advanced.py` → gelişmiş DB testleri
- `tests/test_validators.py` → URL doğrulama testleri
- `tests/test_url_validator.py` → URLValidator testleri
- `tests/test_severity.py` → Severity sınıfı testleri
- `tests/test_vulnerability.py` → Vulnerability modeli testleri
- `tests/test_scan_result.py` → ScanResult modeli testleri
- `siber_savascilar/core/database.py` → 5 tablolu SQLite şeması

---

## Klasör Yapısı (Bu Branch)

```
nursena/
├── GOREVLER.md                               ← bu dosya
├── siber_savascilar/
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py                         ← Görev 1, 2
│   │   ├── database.py                       ← Görev 6
│   │   └── validators.py                     ← Görev 2
│   └── scanners/
│       ├── __init__.py                       ← Görev 3
│       ├── base.py                           ← Görev 3
│       ├── sqli_scanner.py                   ← Görev 4
│       ├── xss_scanner.py                    ← Görev 4
│       ├── port_scanner.py                   ← Görev 4
│       ├── access_control_scanner.py         ← Görev 5
│       ├── misconfig_scanner.py              ← Görev 5
│       └── sensitive_data_scanner.py         ← Görev 5
└── tests/
    ├── __init__.py
    ├── test_scanners.py                      ← Görev 6
    ├── test_models.py                        ← Görev 6
    ├── test_database.py                      ← Görev 6
    ├── test_database_advanced.py             ← Görev 6
    ├── test_validators.py                    ← Görev 6
    ├── test_url_validator.py                 ← Görev 6
    ├── test_severity.py                      ← Görev 6
    ├── test_vulnerability.py                 ← Görev 6
    └── test_scan_result.py                   ← Görev 6
```

---

## Git Komutları

```bash
git checkout -b feature/nursena-karaduman
git add .
git commit -m "feat: core modeller, veritabanı şeması ve tarayıcı modülleri (Nursena Karaduman)"
git push origin feature/nursena-karaduman
```
