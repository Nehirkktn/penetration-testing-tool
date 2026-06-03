# Şevval Duran — Görev Dosyaları (Yazılım Mühendisi)

Bu klasördeki dosyalar, sana atanan görevlere karşılık gelen proje parçalarıdır.
Branch adın: `feature/sevval-duran`

---

## Görev 1 — Geliştirme Ortamı Kurulumu & Belgelenmesi
**İlgili Dosyalar:**
- `Dockerfile` → Python 3.11 slim tabanlı container imajı
- `docker-compose.yml` → tek komutla ayağa kaldırma yapılandırması
- `baslat.sh` → manuel kurulum ve çalıştırma betiği
- `KOMUTLAR.md` → ekip için Git ve çalıştırma komutları rehberi

`docker-compose up --build` komutuyla tüm bağımlılıklar otomatik kurulur,
uygulama `http://localhost:5000` adresinde açılır.

---

## Görev 2 — Web Tabanlı Yönetim Paneli UI/UX Tasarımı
**İlgili Dosyalar:**
- `web/index.html` → panel HTML yapısı (sidebar, dashboard, tarama formu, geçmiş, senaryolar)
- `web/style.css` → koyu tema, CSS değişkenleri, responsive grid
- `web/script.js` → API çağrıları ve dinamik UI güncellemeleri

Panel özellikleri (wireframe → gerçek uygulama):
- **Sidebar:** navigasyon (Dashboard, Yeni Tarama, Geçmiş, Senaryolar)
- **Dashboard:** 4 istatistik kartı (Toplam Tarama, Toplam Zafiyet, Kritik, Yüksek)
- **Yeni Tarama:** hedef URL girişi, modül seçimi (checkbox'lar), tarama başlatma
- **Tarama Geçmişi:** tablo (ID, Hedef, Durum, Zafiyet Sayısı, Tarih), detay/sil işlemleri
- **Senaryolar:** YAML senaryo listesi

---

## Görev 3 — Veritabanı Şeması Tasarımı
**İlgili Dosya:** `siber_savascilar/core/database.py`

5 tablolu SQLite şeması (`SCHEMA_SQL`):

| Tablo | İçerik |
|---|---|
| `users` | Kullanıcı hesapları (id, username, email, password_hash, role) |
| `scan_configs` | Tarama yapılandırmaları (hangi modüller aktif) |
| `scans` | Tarama oturumları (hedef, durum, tarih, süre) |
| `vulnerabilities` | Tespit edilen zafiyetler (scan_id FK, tür, önem, kanıt) |
| `reports` | Rapor yolları (html_path, json_path) |

İndeksler: `severity`, `target_url`, `status` sütunları üzerinde performans indeksleri.
FOREIGN KEY kısıtları ile `ON DELETE CASCADE` bütünlüğü.

---

## Görev 4 — Web Arayüzü Temel İskeleti
**İlgili Dosyalar:**
- `web/index.html` → semantic HTML yapısı, Bootstrap-free saf HTML
- `web/style.css` → CSS custom properties (`--bg-primary`, `--accent` vb.), dark theme
- `web/script.js` → `API` nesnesi (fetch wrapper), modül tooltip içerikleri, live polling

Temel işlevler arayüzden erişilebilir:
- Tarama başlatma (`POST /api/scans`)
- Raporu görüntüleme (`GET /api/scans/<id>/report`)
- Taramayı silme (`DELETE /api/scans/<id>`)
- Senaryo listesi (`GET /api/scenarios`)

---

## Görev 5 — Güvenlik Duvarı Kuralları & Erişim Kontrolü
**İlgili Dosya:** `siber_savascilar/core/database.py`

Veritabanı erişim katmanındaki güvenlik önlemleri:
- `PRAGMA foreign_keys = ON` → referans bütünlüğü zorunlu
- Tüm SQL sorguları parametreli (`?` placeholder) — f-string yasak (BUG-003 düzeltmesi)
- `@contextmanager connection()` → otomatik commit/rollback, bağlantı sızıntısı yok
- Kullanıcı şifreleri `password_hash` olarak saklanır (plain-text yok)

---

## Klasör Yapısı (Bu Branch)

```
sevval/
├── GOREVLER.md                            ← bu dosya
├── Dockerfile                             ← Görev 1
├── docker-compose.yml                     ← Görev 1
├── baslat.sh                              ← Görev 1
├── DAGITIM_PLANI.md                       ← Görev 1
├── KOMUTLAR.md                            ← Görev 1
├── data/
│   └── .gitkeep
├── reports/
│   └── .gitkeep
├── web/
│   ├── index.html                         ← Görev 2, 4
│   ├── style.css                          ← Görev 2, 4
│   └── script.js                          ← Görev 2, 4
├── siber_savascilar/
│   └── core/
│       ├── __init__.py
│       └── database.py                    ← Görev 3, 5
└── tests/
    ├── __init__.py
    └── test_api.py                        ← Görev 4
```

---

## Git Komutları

```bash
git checkout -b feature/sevval-duran
git add .
git commit -m "feat: web arayüzü, veritabanı şeması ve Docker yapılandırması (Şevval Duran)"
git push origin feature/sevval-duran
```
