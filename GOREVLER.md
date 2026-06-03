# Muhammet Sefa Kozan — Görev Dosyaları (Yazılım Mühendisi)

Bu klasördeki dosyalar, sana atanan görevlere karşılık gelen proje parçalarıdır.
Branch adın: `feature/sefa-kozan`

---

## Görev 1 — Araç Kurulumu & Ekip Yapılandırması
**İlgili Dosyalar:**
- `requirements.txt` → tüm bağımlılıklar (Flask, requests, pyyaml, reportlab, python-nmap, pytest)
- `setup.py` → pip ile kurulum tanımı (`pip install -e .`)
- `.gitignore` → Git dışında tutulacak dosyalar
- `.dockerignore` → Docker build'e dahil edilmeyecek dosyalar

Bu dosyalar projenin kurulum ortamını (bağımlılıklar, paket yapısı, versiyon)
standart hale getirir. Ekip bu dosyalarla aynı ortamda çalışır.

---

## Görev 2 — Entegrasyon Yöntemleri Araştırması
**İlgili Dosya:** `siber_savascilar/scanners/__init__.py`

`SCANNER_REGISTRY` sözlüğü, desteklenen tüm araç entegrasyonlarının kayıt noktasıdır:
```python
SCANNER_REGISTRY = {
    "ports":          PortScanner,       # Nmap entegrasyonu
    "sqli":           SQLiScanner,       # Manuel SQLi
    "xss":            XSSScanner,
    "misconfig":      MisconfigScanner,
    "sensitive_data": SensitiveDataScanner,
    "access_control": AccessControlScanner,
    "scenarios":      ScenarioScanner,   # YAML motoru
    "sqlmap":         SQLMapScanner,     # SQLMap entegrasyonu
}
```

---

## Görev 3 — SQLMap Entegrasyon Modülü
**İlgili Dosya:** `siber_savascilar/scanners/sqlmap_scanner.py`

SQLMap wrapper modülü:
- Sistemde `sqlmap` binary'si varsa subprocess ile çalıştırır
- Yoksa yerleşik `sqli_scanner.py`'ye (kendi SQLi tarayıcımız) düşer (fallback)
- SQLMap çıktısını parse ederek `Vulnerability` nesnesi üretir
- Farklı veritabanı sistemlerini (MySQL, PostgreSQL, MSSQL, SQLite) destekler
- URL, parametreler, veritabanı türü yapılandırılabilir

---

## Görev 4 — Kimlik Doğrulama Mekanizmaları & Güvenlik
**İlgili Dosya:** `siber_savascilar/core/validators.py`

`URLValidator` ve `TargetValidator` sınıfları:
- **SSRF koruması:** Özel/dahili IP aralıkları (`10.x`, `192.168.x`, `127.x`) opsiyonel engelleme
- **CRLF koruması:** Kontrol karakterleri (`\x00-\x1f`) reddedilir
- Sadece `http` ve `https` protokolleri kabul edilir
- `normalize()`: protokol ekleme ve URL temizleme

---

## Görev 5 — Orchestrator & Entegrasyon Katmanı
**İlgili Dosyalar:**
- `siber_savascilar/orchestrator.py` → `Orchestrator` sınıfı; tüm modülleri koordine eder
- `siber_savascilar/cli.py` → CLI arayüzü
- `siber_savascilar/__init__.py`
- `siber_savascilar/__main__.py`

`Orchestrator.scan()` akışı:
1. URL normalize + doğrulama
2. Veritabanında scan kaydı oluşturma
3. Seçilen modülleri sırayla çalıştırma (`SCANNER_REGISTRY`)
4. Tüm bulgular `ScanResult`'a toplama
5. Sonuç veritabanına yazma

---

## Görev 6 — Güvenlik Açığı Raporu & Giderme
**İlgili Dosyalar:**
- `tests/test_orchestrator.py` → entegrasyon testleri
- `siber_savascilar/core/validators.py` → güvenlik açıklarının giderildiği yer
  (BUG-003: f-string SQL injection riski → parametreli sorgular)

---

## Klasör Yapısı (Bu Branch)

```
sefa/
├── GOREVLER.md                            ← bu dosya
├── requirements.txt                       ← Görev 1
├── setup.py                               ← Görev 1
├── .gitignore                             ← Görev 1
├── .dockerignore                          ← Görev 1
├── siber_savascilar/
│   ├── __init__.py                        ← Görev 5
│   ├── __main__.py                        ← Görev 5
│   ├── orchestrator.py                    ← Görev 5
│   ├── cli.py                             ← Görev 5
│   ├── core/
│   │   ├── __init__.py
│   │   └── validators.py                  ← Görev 4
│   └── scanners/
│       ├── __init__.py                    ← Görev 2
│       ├── base.py
│       └── sqlmap_scanner.py              ← Görev 3
└── tests/
    ├── __init__.py
    └── test_orchestrator.py               ← Görev 6
```

---

## Git Komutları

```bash
git checkout -b feature/sefa-kozan
git add .
git commit -m "feat: SQLMap entegrasyonu, orchestrator ve proje yapılandırması (Sefa Kozan)"
git push origin feature/sefa-kozan
```
