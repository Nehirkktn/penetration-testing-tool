# Nehir Kökten — Görev Dosyaları (Proje Yöneticisi)

Bu klasördeki dosyalar, sana atanan görevlere karşılık gelen proje parçalarıdır.
Branch adın: `feature/nehir-kokten`

---

## Görev 1 — Gereksinim Toplama & Paydaş Analizi
**İlgili Dosya:** `docs/MIMARI.md`

Proje için fonksiyonel ve teknik gereksinimler, sistem mimarisi ve katmanları
bu dokümanda özetlenmiştir. Paydaşlar (kullanıcı, sistem yöneticisi) ve
beklentileri mimarinin 3 katmanlı yapısında (Sunum / İş Mantığı / Veri) yansıtılmıştır.

---

## Görev 2 — Raporlama Modülü Tasarımı & Planlaması
**İlgili Dosya:** `siber_savascilar/reporting/generator.py`

Raporlama modülünün tasarımı bu dosyada hayata geçirilmiştir:
- Desteklenen formatlar: **HTML**, **JSON**, **PDF**
- Raporlarda yer alan bilgiler: zafiyet tanımı, risk seviyesi (Critical/High/Medium/Low/Info),
  hedef URL, payload, kanıt, CWE referansı, çözüm önerisi
- Diğer bileşenlerle entegrasyon: `ScanResult` ve `Vulnerability` modelleri üzerinden
  veri alır; `api/server.py` aracılığıyla web paneline bağlanır

---

## Görev 3 — Raporlama Kullanıcı Arayüzü Tasarımı
**İlgili Dosyalar:**
- `siber_savascilar/reporting/generator.py` → HTML şablonu (`HTML_TEMPLATE`, `VULN_TEMPLATE`)
- `siber_savascilar/reporting/fonts/DejaVuSans.ttf`
- `siber_savascilar/reporting/fonts/DejaVuSans-Bold.ttf`

Raporun görsel tasarımı:
- Koyu üst başlık (Tarama ID, Hedef, Süre, Modüller)
- 6 renk kodlu istatistik kartı (Kritik → kırmızı, Yüksek → turuncu, ...)
- Her zafiyet için sol kenarda severity rengiyle belirlenmiş kart yapısı
- Türkçe PDF desteği için DejaVu Sans fontları
- Özelleştirme seçenekleri: `ReportGenerator(output_dir=...)` parametresi

---

## Görev 4 — Temel Raporlama Modülü Geliştirmesi
**İlgili Dosyalar:**
- `siber_savascilar/reporting/generator.py` → `ReportGenerator` sınıfı
- `siber_savascilar/reporting/__init__.py`
- `tests/test_reporting.py`

`ReportGenerator` sınıfının 3 ana metodu:
- `generate_html(scan_result)` → HTML rapor üretir, dosya yolunu döndürür
- `generate_json(scan_result)` → JSON rapor üretir
- `generate_pdf(scan_result)` → reportlab ile PDF üretir (yoksa None döner)

Zafiyet tarama motorundan gelen `ScanResult` nesnesi doğrudan bu metodlara verilir.

---

## Görev 5 — OWASP ZAP / Harici Araç Entegrasyonu
**İlgili Dosya:** `siber_savascilar/api/server.py`

Tarama sonuçlarının analizi ve raporlanması API katmanında gerçekleşir:
- `POST /api/scans` → tarama başlatır
- `GET /api/scans/<id>/report` → HTML raporu görüntüler
- `GET /api/scans/<id>/report.pdf` → PDF raporu indirir
- `GET /api/scans/<id>/report.json` → JSON raporu indirir
- `GET /api/scanners` → mevcut tarayıcı modüllerini listeler

---

## Görev 6 — Entegrasyon & Tamamlama
**İlgili Dosyalar:**
- `siber_savascilar/api/server.py` → tüm bileşenlerin birleştiği API katmanı
- `siber_savascilar/api/__init__.py`
- `docs/KURULUM.md` → kurulum ve yapılandırma rehberi
- `docs/GOREV_DURUMU.md` → proje görev durumu özeti
- `README.md` → projenin genel tanıtımı

---

## Klasör Yapısı (Bu Branch)

```
nehir/
├── README.md
├── GOREVLER.md                          ← bu dosya
├── docs/
│   ├── MIMARI.md                        ← Görev 1
│   ├── KURULUM.md                       ← Görev 6
│   └── GOREV_DURUMU.md                  ← Görev 6
├── siber_savascilar/
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── generator.py                 ← Görev 2, 3, 4
│   │   └── fonts/
│   │       ├── DejaVuSans.ttf           ← Görev 3
│   │       └── DejaVuSans-Bold.ttf      ← Görev 3
│   └── api/
│       ├── __init__.py
│       └── server.py                    ← Görev 5, 6
└── tests/
    └── test_reporting.py                ← Görev 4
```

---

## Git Komutları

```bash
git checkout -b feature/nehir-kokten
git add .
git commit -m "feat: raporlama modülü ve API entegrasyonu (Nehir Kökten)"
git push origin feature/nehir-kokten
```
