# 📋 Buluşma Dağılım Planı

> Bu doküman Trello panosundaki görev dağılımına göre, **her arkadaşın hangi
> dosyaları kendi branch'inde push'layacağını** gösterir. Buluşmada (Meet
> veya yüz yüze) bu listeye göre ilerleyin.

---

## 🎯 Ana Mantık

Sefa'nın WhatsApp'ta dediği gibi:
> "Kaynak kodları görevlerimize göre ayırırız, kendi branch'lerine
> pushlarlar, proje yine birleşir. Hem de herkesin commit geçmişi
> ana repoda durmuş olur."

Yani:
1. Yeni repo açılır (Nehir açar, PM olduğu için)
2. **Sadece çatı dosyaları** (`README.md`, `requirements.txt`, `setup.py`,
   `Dockerfile`, `.gitignore`, `LICENSE`) `main` branch'e Nehir tarafından
   push'lanır
3. Her arkadaş **kendi branch'ini açar**, **kendi sorumlu olduğu dosyaları**
   commit'leyip push'lar
4. Hepsi tamamlandığında Pull Request açar, Nehir merge eder
5. Commit geçmişinde her dosyanın sahibi belli olur

---

## 👥 Kişi ↔ Dosya Eşleştirmesi

### 1️⃣ Nehir Kökten (Proje Yöneticisi)

**Trello Görevleri:**
- ✅ Final Sunum İçeriğinin Hazırlanması
- ✅ Güvenlik Açığı Raporlama Modülü Temel Tasarımı ve Veri Entegrasyonu
- ✅ Güvenlik Açığı Raporlama Modülü Planlaması
- ✅ Gereksinim Toplama ve Paydaş Analizi
- 🔄 Güvenlik Açığı Raporlama Modülü Arayüz Tasarımı
- 🔄 Güvenlik Açığı Tarama Aracı Entegrasyonu (Yapılacaklar)

**Branch adı:** `nehir-raporlama-mimari`

**Push'layacağı dosyalar:**
```
docs/MIMARI.md                                ← Mimari dokümanı
docs/GOREV_DURUMU.md                          ← Trello görev haritası
siber_savascilar/reporting/__init__.py        ← Rapor modülü
siber_savascilar/reporting/generator.py       ← HTML/JSON/PDF üretici
siber_savascilar/orchestrator.py              ← Tarayıcı orkestratörü (entegrasyon)
```

**Ayrıca PM olarak Nehir'in yapacağı:**
- Repo'yu açmak (GitHub'da)
- `main` branch'e ortak dosyaları push'lamak: `README.md`, `requirements.txt`,
  `setup.py`, `Dockerfile`, `.gitignore`, `LICENSE`, `baslat.sh`
- Diğer ekip üyelerini repo'ya **Collaborator** olarak eklemek
- Pull Request'leri merge etmek

---

### 2️⃣ Nursena Karaduman

**Trello Görevleri:**
- ✅ Proje Analizi ve Kapsam Belirleme
- ✅ Zafiyet Tarama Motoru Gereksinim Analizi
- 🔄 Proje Toparlama ve Test Senaryoları Geliştirme
- 🔄 Zafiyet Tarama Motoru Temel Fonksiyonlarının Geliştirilmesi
- 🔄 Zafiyet Tarama Motoru Modül Tasarımı (Yapılacaklar)

**Branch adı:** `nursena-tarayicilar`

**Push'layacağı dosyalar:**
```
siber_savascilar/core/database.py                       ← SQLite şema + DB
siber_savascilar/scanners/__init__.py                   ← Scanner registry
siber_savascilar/scanners/base.py                       ← BaseScanner abstract
siber_savascilar/scanners/port_scanner.py               ← Port tarama
siber_savascilar/scanners/sqli_scanner.py               ← SQL Injection
siber_savascilar/scanners/xss_scanner.py                ← XSS
siber_savascilar/scanners/misconfig_scanner.py          ← Yapılandırma
siber_savascilar/scanners/sensitive_data_scanner.py     ← Hassas veri
siber_savascilar/scanners/access_control_scanner.py     ← Erişim kontrolü
```

---

### 3️⃣ Muhammed Baki Başbay

**Trello Görevleri:**
- ✅ Teknoloji Araştırması ve Seçimi
- 🔄 Özelleştirilebilir Test Senaryoları için Temel Altyapının Oluşturulması
- 🔄 Özelleştirilebilir Test Senaryoları Araştırması
- 🔄 Özelleştirilebilir Test Senaryoları Yönetim Paneli Tasarımı (Yapılacaklar)
- 🔄 Sızma Testi Senaryoları Geliştirme (Yapılacaklar)

**Branch adı:** `muhammed-senaryolar`

**Push'layacağı dosyalar:**
```
siber_savascilar/scanners/scenario_scanner.py     ← YAML senaryo motoru
scenarios_data/01-gizli-admin-panel.yaml          ← Örnek senaryo 1
scenarios_data/02-backup-file-exposure.yaml       ← Örnek senaryo 2
scenarios_data/03-git-exposure.yaml               ← Örnek senaryo 3
```

---

### 4️⃣ Şevval Duran

**Trello Görevleri:**
- ✅ Web Tabanlı Yönetim Paneli Temel Modül Arayüz Tasarımı
- ✅ Veritabanı Şeması Tasarımı
- ✅ Geliştirme Ortamı Kurulumu
- 🔄 Web Tabanlı Yönetim Paneli Tasarımı
- 🔄 Güvenlik Duvarı Kurallarının Optimizasyonu (İncelemede)

**Branch adı:** `sevval-frontend`

**Push'layacağı dosyalar:**
```
web/index.html              ← Ana arayüz
web/style.css               ← Modern koyu tema
web/script.js               ← Frontend mantığı
docs/KURULUM.md             ← Geliştirme ortamı dokümanı
siber_savascilar/api/__init__.py
siber_savascilar/api/server.py                    ← Flask backend (frontend için)
```

> **Not Şevval'e:** Backend (`api/server.py`) frontend'e bağlı olduğu için sende
> kalıyor. İstersen Sefa'yla ortak commit'leyebilirsin (`Co-authored-by` ile).

---

### 5️⃣ Mehmet Sefa Kozan

**Trello Görevleri:**
- ✅ Teknoloji Entegrasyon Araştırması
- ✅ SQLMap Entegrasyonu için Temel Modül Geliştirilmesi
- ✅ Güvenlik Açıklarının Giderilmesi ve Raporlanması
- ✅ Proje Yönetimi ve İş Birliği Araçları
- 🔄 Metasploit Entegrasyon Modülü Tasarımı (Yapılacaklar)

**Branch adı:** `sefa-sqlmap-test`

**Push'layacağı dosyalar:**
```
siber_savascilar/__init__.py                  ← Paket meta
siber_savascilar/__main__.py                  ← Giriş noktası
siber_savascilar/cli.py                       ← CLI arayüzü
siber_savascilar/core/__init__.py
siber_savascilar/core/models.py               ← Vulnerability, ScanResult
siber_savascilar/core/validators.py           ← URL doğrulama, SSRF koruma
siber_savascilar/scanners/sqlmap_scanner.py   ← SQLMap wrapper
tests/__init__.py
tests/test_models.py                          ← 10 test
tests/test_validators.py                      ← 9 test
tests/test_database.py                        ← 6 test
tests/test_severity.py                        ← 32 test
tests/test_vulnerability.py                   ← 24 test
tests/test_scan_result.py                     ← 38 test
tests/test_url_validator.py                   ← 64 test
tests/test_scanners.py                        ← 35 test
tests/test_orchestrator.py                    ← 12 test
tests/test_reporting.py                       ← 23 test
tests/test_api.py                             ← 28 test
tests/test_database_advanced.py               ← 26 test
tests/test_scenarios.py                       ← 22 test
```

> **Not Sefa'ya:** Test paketi (394 test) tamamen senin sorumluluğunda
> oluyor — bu mantıklı, çünkü Trello'da "Güvenlik Açıklarının Giderilmesi"
> görevi sendeydi.

---

## 📂 Çatı dosyaları (Nehir push'lar, `main` branch)

Bunlar herkesin ortak kullandığı, kimseye özel olmayan dosyalar:

```
README.md
requirements.txt
setup.py
.gitignore
LICENSE
baslat.sh
Dockerfile                      ← Docker imaj tanımı (Mira/Sen ekledin)
docker-compose.yml              ← Tek komutla başlatma
.dockerignore                   ← Docker'ın gereksiz dosyaları atlaması için
DAGITIM_PLANI.md                ← Bu doküman
KOMUTLAR.md                     ← Git komutları rehberi
data/.gitkeep
reports/.gitkeep
```

> **Önemli:** Docker dosyaları (`Dockerfile`, `docker-compose.yml`,
> `.dockerignore`) Nehir tarafından `main`'e push'lanır. Mira'nın katkısı
> olarak commit mesajına ekleyebiliriz:
> ```bash
> git commit -m "Docker entegrasyonu ekle (Mira tarafından)" \
>   --author="Mira <mira-email@adres.com>"
> ```

---

## ⏱️ Buluşma Akışı (Tahmini 1 saat)

| Süre | Adım | Kim Yapar |
|---|---|---|
| 0-5dk | Nehir GitHub'da yeni repo açar (Public, README yok) | Nehir |
| 5-10dk | Nehir herkesi Collaborator olarak ekler | Nehir |
| 10-15dk | Nehir çatı dosyalarını `main`'e push'lar | Nehir |
| 15-45dk | Herkes kendi branch'ini açar, kendi dosyalarını push'lar | Hepsi paralel |
| 45-55dk | Pull Request'ler açılır | Hepsi |
| 55-60dk | Nehir PR'leri sırayla merge eder | Nehir |

**Sıralama önemli:**
1. Önce Sefa (çekirdek modeller — herkes ona bağımlı)
2. Sonra Nursena (tarayıcılar — modellere bağımlı)
3. Sonra Muhammed (senaryolar — base scanner'a bağımlı)
4. Sonra Şevval (backend + frontend — tarayıcılara bağımlı)
5. En son Nehir (raporlama + orkestratör — hepsine bağımlı)

> Bu sıra önemli çünkü çakışma olmasın. Birinin merge'i diğerinin push'undan
> önce gelirse Pull Request'te conflict çıkar.

---

## ⚠️ Önemli Notlar

1. **Bu son sürüm değil.** Sefa 1 Haziran'a kadar Malatya'da olduğu için
   sonradan ince ayar yapacaksınız. Şimdiki amaç görevleri bölmek ve
   commit geçmişini düzgün oluşturmak.

2. **Mevcut Trello panosu açık kalsın** — hocaya teslimde "kim ne yaptı"
   sorgusunda kanıt olur.

3. **Eski repo (PM Nehir'in açtığı orijinal repo) silinmesin.** Yeni repo'nun
   README'sine link verilecek.

4. **Docker dosyası kalsın.** Bu sayede arkadaşlar projeyi `docker build`
   ile tek komutla çalıştırabilir.

5. Bir kişi merge'lerken çakışma çıkarsa **paniklemeyin** — bana sorun,
   nasıl çözüleceğini gösteririm.
