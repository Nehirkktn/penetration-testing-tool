# Muhammed Baki Başbay — Görev Dosyaları (Yazılım Mühendisi)

Bu klasördeki dosyalar, sana atanan görevlere karşılık gelen proje parçalarıdır.
Branch adın: `feature/baki-basbay`

---

## Görev 1 — Teknoloji Araştırması & Seçimi
**İlgili Dosyalar:**
- `siber_savascilar/scanners/scenario_scanner.py` → Nuclei referanslı YAML mimarisi
- `siber_savascilar/core/models.py` → `Severity`, `VulnType` sabitleri

Teknoloji kararları:
- **Dil:** Python 3.9+ (cross-platform, geniş güvenlik ekosistemi)
- **Senaryo formatı:** YAML (okunabilir, yaygın, `pyyaml` ile kolay parse)
- **Mimari referans:** Nuclei (ProjectDiscovery) şablon yapısı

---

## Görev 2 — Özelleştirilebilir Test Senaryoları Araştırması
**İlgili Dosyalar:**
- `scenarios_data/01-gizli-admin-panel.yaml`
- `scenarios_data/02-backup-file-exposure.yaml`
- `scenarios_data/03-git-exposure.yaml`

YAML senaryo formatı:
```yaml
id: unique-id
info:
  name: "Senaryo Adı"
  author: "yazar"
  severity: "High"          # Critical / High / Medium / Low / Informational
  description: "Açıklama"
  cwe: "CWE-284"
  remediation: "Çözüm"
requests:
  - method: GET
    path:
      - "{{target_url}}/admin"
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Welcome admin"]
        condition: and   # or / and
```

Kullanıcılar bu formatta kendi `.yaml` dosyalarını `scenarios_data/` klasörüne ekleyerek
özel test senaryoları tanımlayabilir.

---

## Görev 3 — Senaryo Yönetim Paneli
**İlgili Dosya:** `siber_savascilar/scanners/scenario_scanner.py`

`ScenarioScanner` sınıfı senaryo yönetimini otomatik yapar:
- `scenarios_data/` klasöründeki tüm `.yaml` / `.yml` dosyalarını otomatik yükler
- Yeni dosya eklenince sistem yeniden başlatıldığında otomatik tanır
- Hatalı YAML dosyaları atlanır (crash olmaz)
- Web paneli `/api/scenarios` endpoint'i üzerinden senaryo listesini gösterir

---

## Görev 4 — Özelleştirilebilir Test Senaryoları Altyapısı
**İlgili Dosyalar:**
- `siber_savascilar/scanners/scenario_scanner.py` → senaryo motoru çekirdeği
- `scenarios_data/01-gizli-admin-panel.yaml` → OWASP A01 (Broken Access)
- `scenarios_data/02-backup-file-exposure.yaml` → OWASP A05 (Misconfiguration) Critical
- `scenarios_data/03-git-exposure.yaml` → OWASP A05 High

Altyapı özellikleri:
- **Esnek matcher sistemi:** `status` (HTTP kodu), `word` (içerik eşleşme), `regex` (pattern)
- **AND / OR koşul mantığı:** tüm/herhangi matcher eşleşmesi
- **Yapılandırılabilir parametreler:** `{{target_url}}` değişkeni otomatik doldurulur
- **Genişletilebilir:** yeni matcher türleri sisteme kolayca eklenebilir
- **Bağımsız YAML:** her senaryo kendi başına çalışır, başkasına bağımlılık yok

---

## Görev 5 — Log Analizi & Şüpheli Aktivite Tespiti
**İlgili Dosyalar:**
- `siber_savascilar/scanners/scenario_scanner.py` → her senaryo çalışmasının loglanması
- `siber_savascilar/core/models.py` → `ScanStatus` (pending/running/completed/error/timeout)

`ScanStatus` sınıfı tüm tarama durumlarını izler:
- `TIMEOUT` → şüpheli yavaş yanıt / IDS müdahalesi
- `ERROR` → bağlantı hatası / beklenmeyen durum
- Her zafiyet `discovered_at` zaman damgasıyla kayıt altına alınır

---

## Görev 6 — Dokümantasyon Güncelleme
**İlgili Dosya:** `LICENSE`

Projenin lisans belgesi. Teknik dokümantasyonun geri kalanı
Nehir Kökten'in `docs/` klasöründe birleştirilmiştir.

---

## Klasör Yapısı (Bu Branch)

```
baki/
├── GOREVLER.md                                ← bu dosya
├── LICENSE                                    ← Görev 6
├── scenarios_data/
│   ├── 01-gizli-admin-panel.yaml             ← Görev 2, 4
│   ├── 02-backup-file-exposure.yaml          ← Görev 2, 4
│   └── 03-git-exposure.yaml                  ← Görev 2, 4
├── siber_savascilar/
│   ├── core/
│   │   ├── __init__.py
│   │   └── models.py                         ← Görev 1, 5
│   └── scanners/
│       ├── __init__.py
│       ├── base.py
│       └── scenario_scanner.py               ← Görev 3, 4
└── tests/
    ├── __init__.py
    └── test_scenarios.py                     ← Görev 4
```

---

## Git Komutları

```bash
git checkout -b feature/baki-basbay
git add .
git commit -m "feat: YAML senaryo motoru ve özelleştirilebilir test altyapısı (Baki Başbay)"
git push origin feature/baki-basbay
```
