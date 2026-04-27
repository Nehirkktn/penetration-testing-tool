# 📋 SİBER SAVAŞÇILAR — Proje Genel Durum Raporu

> **Hazırlayan:** Nursena Karaduman  
> **Tarih:** 27 Nisan 2026  
> **Proje:** Penetration Testing Tool — Sızma Testi Otomasyon Aracı  
> **Üniversite:** Fırat Üniversitesi — Yazılım Mühendisliği Temelleri Dersi  
> **Metodoloji:** Scrum  

---

## 1. Proje Özeti

**Siber Savaşçılar**, web uygulamaları ve ağ sistemleri üzerinde otomatik sızma testleri gerçekleştiren, OWASP Top 10 standartlarını referans alan Python tabanlı bir güvenlik otomasyon aracıdır. Proje; zafiyet tarama, güvenlik açığı analizi ve raporlama modüllerini tek bir çatı altında toplamayı hedeflemektedir.

---

## 2. Ekip ve Rol Dağılımı

| İsim | Rol | Branch |
|:---|:---|:---|
| **Nehir Kökten** | Proje Yöneticisi | `pm-nehir` |
| **Nursena Karaduman** | Yazılım Mühendisi | `dev-nursena` |
| **Muhammed Baki Başbay** | Yazılım Mühendisi | `dev-muhammed` |
| **Şevval Duran** | Yazılım Mühendisi | `dev-sevval` |
| **M. Sefa Kozan** | Yazılım Mühendisi | `dev-sefa` |

---

## 3. Haftalık İlerleme Özeti

### Hafta 1 (9–15 Mart 2026) — Proje Başlatma ve Altyapı Hazırlığı
- GitHub deposu oluşturuldu, ekip erişim yetkileri düzenlendi. *(Nehir)*
- Python dili ve kütüphane analizi yapıldı; `python-nmap`, `requests` uyumluluk testleri gerçekleştirildi. *(Muhammed)*
- Geliştirme ortamı kuruldu; Nmap, SQLMap, Metasploit için ortam değişkenleri yapılandırıldı. *(Şevval)*
- Proje takvimi oluşturuldu, GitHub Projects üzerinden görev kategorileri belirlendi. *(Sefa)*
- Hedeflenen zafiyet listesi çıkarıldı; SQL Injection ve Port Tarama parametreleri dökümante edildi. *(Nursena)*

### Hafta 3 (23–29 Mart 2026) — Mimari Tasarım ve Veri Modelleme
- 3 katmanlı (Layered Architecture) sistem mimarisi tasarlandı, bileşenler arası veri akışı diyagramlandı. *(Nehir)*
- Veritabanı ER diyagramı hazırlandı; Primary Key / Foreign Key ilişkileri ve normalizasyon tamamlandı. *(Nursena)*
- Kullanıcı arayüzü wireframe ve mockup tasarımları çizildi. *(Muhammed)*

---

## 4. Üye Bazlı Katkı Detayları

### 4.1 Nehir Kökten — Proje Yöneticisi (`pm-nehir`)

**Tamamlanan Çıktılar:**

- `Gereksinim_Analizi.md` — Fonksiyonel gereksinimler (FR-01 → FR-04), teknik gereksinimler (TR-01 → TR-04) ve paydaş analizi tablosu hazırlandı.
- `mimari_tasarim.md` — 3 katmanlı mimari (Sunum / İş Mantığı / Veri) ve sistem veri akışı (5 adımlık yaşam döngüsü) belgelendi.
- `raporlama_modulu_planlamasi.md` — HTML, PDF ve CSV/JSON çıktı formatları, rapor içerik yapısı ve UI entegrasyonu planlandı.
- `rapor_sablonu.md` — Canlı HTML rapor şablonu oluşturuldu.

**Değerlendirme:** Proje yönetimi ve dokümantasyon sorumlulukları eksiksiz yerine getirilmiştir. Mimari karar dokümanları projenin teknik yönünü başarıyla yönlendirmiştir.

---

### 4.2 Nursena Karaduman — Yazılım Mühendisi (`dev-nursena`)

**Tamamlanan Çıktılar:**

- `docs/proje-kapsami.md` — OWASP Top 10 (2021) tüm kategorileri detaylıca analiz edilerek kapsam belirleme raporu hazırlandı.
- `docs/veritabani-semasi.md` — 5 tablolu (USERS, SCAN_CONFIGS, SCANS, VULNERABILITIES, REPORTS) veritabanı mimarisi tasarlandı.
- `docs/veritabani-semasi.png` — ER diyagramı görsel olarak oluşturuldu.
- `scanner_engine/database.py` — SQLite bağlantısı ve tablo oluşturma fonksiyonları implement edildi.
- `scanner_engine/port_scanner.py` — Nmap ile port tarama modülü geliştirildi (80, 443, 8080, 3306 portları).
- `scanner_engine/vuln_scanner.py` — SQL Injection ve XSS payload tabanlı zafiyet tarama modülü geliştirildi.
- `scanner_engine/main.py` — Tarama orkestratörü; port tarama + zafiyet tarama + DB kayıt akışı entegre edildi.
- `siber_savascılar.db` — Veritabanı gerçek ortamda çalıştırılarak oluşturuldu.

**Değerlendirme:** Ekipte çalışan Python kodu üreten ve veritabanını gerçek ortamda test eden üyedir. Kapsam dokümantasyonu ve veri modeli tasarımı güçlüdür.

---

### 4.3 Muhammed Baki Başbay — Yazılım Mühendisi (`dev-muhammed`)

**Tamamlanan Çıktılar:**

- `Teknoloji_Secim_Raporu.md` — Python, FastAPI, React.js, Celery+Redis, PostgreSQL teknoloji yığını karşılaştırmalı tablolarla seçildi ve gerekçelendirildi.
- `Ozel_Senaryolar_Mimarisi.md` — Nuclei referanslı YAML tabanlı özelleştirilebilir senaryo sistemi mimarisi tasarlandı.
- `motor/senaryo_okuyucu.py` — YAML senaryo dosyalarını okuyup Python dict'e çeviren modül yazıldı.
- `motor/ozel_tarama_motoru.py` — YAML senaryolarındaki kuralları hedefe uygulayan HTTP istek motoru geliştirildi.
- `senaryolar/ornek_senaryo.yaml` — Örnek bağlantı testi senaryosu oluşturuldu.
- `test_et.py` — Senaryo okuma ve çalıştırma entegrasyon testi yazıldı.
- `ui_designs/mockup.png` ve `wireframe.png` — Arayüz tasarım görselleri oluşturuldu.

**Değerlendirme:** Teknoloji araştırması kapsamlıdır. Özelleştirilebilir senaryo motoru özgün ve genişletilebilir bir mimari sunar.

---

### 4.4 Şevval Duran — Yazılım Mühendisi (`dev-sevval`)

**Tamamlanan Çıktılar:**

- `sizma_testi_gelistirme_ortami.md` — Python, Nmap, SQLMap, Metasploit ve Burp Suite kurulum adımları (Linux ve Windows için) detaylıca dokümante edildi.
- `index.html` — Dashboard, Raporlar ve Test Senaryoları sekmelerine sahip yönetim paneli prototype'ı oluşturuldu.
- `style.css` — Panel için temel CSS stilleri yazıldı.
- `script.js` — Sekme geçişi ve tarama başlatma simülasyonu geliştirildi.
- `uiux_tasarim_plani.docx` — UI/UX tasarım planı hazırlandı.

**Değerlendirme:** Geliştirme ortamı kurulum rehberi ekip için kritik bir referans kaynağı olmuştur. Frontend prototype projenin görsel yönünü somutlaştırmıştır.

---

### 4.5 M. Sefa Kozan — Yazılım Mühendisi (`dev-sefa`)

**Tamamlanan Çıktılar:**

- `docs/teknoloji-entegrasyon-arastirmasi.md` — Nmap (XML), SQLMap (subprocess), Metasploit (RPC API), Burp Suite (REST API) entegrasyon yöntemleri araştırıldı.
- `docs/sqlmap-kullanim.md` ve `docs/sqlmap-teknik.md` — SQLMap kullanım kılavuzu ve teknik dokümantasyon hazırlandı.
- `src/config/sqlmap_config.py` — SQLMap yapılandırma sınıfı implement edildi.
- `src/models/scan_result.py` — Tarama sonuçları veri modeli oluşturuldu (`ScanResult`, `ScanStatus` sınıfları).
- `src/parsers/sqlmap_parser.py` — SQLMap çıktısını parse eden modül geliştirildi.
- `src/scanners/sqlmap_scanner.py` — `subprocess` tabanlı tam SQLMap tarayıcı sınıfı yazıldı (logging, custom exception, timeout yönetimi dahil).
- `src/utils/validators.py` — URL ve IP adresi doğrulama yardımcı sınıfı geliştirildi.
- `tests/test_sqlmap_config.py`, `test_sqlmap_parser.py`, `test_sqlmap_scanner.py`, `test_validators.py` — Kapsamlı unit test seti yazıldı.

**Değerlendirme:** En kapsamlı ve profesyonel Python kod tabanını oluşturmuştur. Unit test altyapısı projenin kalite güvencesine önemli katkı sağlamaktadır.

---

## 5. Modül Tamamlanma Durumu

| Modül | Sorumlu | Durum | Notlar |
|:---|:---|:---|:---|
| Gereksinim Analizi | Nehir | ✅ Tamamlandı | FR ve TR gereksinimleri belgelenmiş |
| Sistem Mimarisi | Nehir | ✅ Tamamlandı | 3 katmanlı mimari tasarlandı |
| Raporlama Planı | Nehir | ✅ Tamamlandı | HTML/PDF/CSV formatları planlandı |
| Veritabanı Tasarımı | Nursena | ✅ Tamamlandı | 5 tablo, ER diyagramı hazır |
| Port Tarama Modülü | Nursena | ✅ Tamamlandı | Nmap entegrasyonu çalışıyor |
| SQLi / XSS Tarama | Nursena | ✅ Tamamlandı | Payload tabanlı test çalışıyor |
| Tarama Orkestratörü | Nursena | ✅ Tamamlandı | main.py ile entegre |
| Teknoloji Analizi | Muhammed | ✅ Tamamlandı | Karşılaştırmalı tablo hazır |
| YAML Senaryo Motoru | Muhammed | ✅ Tamamlandı | Çalışan prototype mevcut |
| UI Wireframe/Mockup | Muhammed | ✅ Tamamlandı | Görseller hazır |
| Geliştirme Ortamı Kurulum | Şevval | ✅ Tamamlandı | Linux + Windows adımları |
| Frontend Prototype | Şevval | ✅ Tamamlandı | HTML/CSS/JS panel mevcut |
| SQLMap Entegrasyonu | Sefa | ✅ Tamamlandı | subprocess + parser + model |
| Entegrasyon Araştırması | Sefa | ✅ Tamamlandı | 4 araç için yöntem belirlendi |
| Unit Test Altyapısı | Sefa | ✅ Tamamlandı | 4 test dosyası mevcut |
| **Yeni Test Senaryoları** | **Nursena** | 🔄 **Devam Ediyor** | OWASP kapsamı genişletilecek |
| **Bug Raporu** | **Nursena** | 🔄 **Devam Ediyor** | Kod incelemesi yapılacak |
| Backend API | — | ❌ Başlanmadı | FastAPI entegrasyonu planlandı |
| React Frontend | — | ❌ Başlanmadı | Prototype aşamasında |
| PDF Rapor Üretimi | — | ❌ Başlanmadı | pdfkit planlandı |
| Metasploit Entegrasyonu | — | ❌ Başlanmadı | RPC API planlandı |

---

## 6. Teknik Borç ve Eksikler

### 6.1 Kritik Eksikler
- `port_scanner.py` içindeki Nmap yolu (`C:\Program Files (x86)\Nmap`) sadece Windows'a özgü hard-code edilmiştir. Linux ortamında çalışmaz.
- `main.py` içinde `http://` prefix'i hem `main.py` hem de `vuln_scanner.py` tarafından ayrı ayrı eklenmekte, bu durum URL çifte yazılmasına neden olabilir.
- Veritabanı dosyası `siber_savascılar.db` Türkçe karakter (`ı`) içeriyor; bazı işletim sistemlerinde dosya yolu sorununa yol açabilir.

### 6.2 Mimari Tutarsızlıklar
- Nursena'nın `veritabani-semasi.md`'de tasarladığı 5 tablo (USERS, SCAN_CONFIGS, SCANS, VULNERABILITIES, REPORTS) ile `database.py`'de implement edilen 2 tablo (taramalar, zafiyetler) uyumsuz.
- Sefa'nın `ScanResult` modeli ile Nursena'nın veritabanı şeması henüz entegre edilmemiş; her iki bileşen bağımsız çalışmaktadır.
- Muhammed'in YAML senaryo motoru ile Nursena'nın ana tarama orkestratörü birbirine bağlanmamıştır.

### 6.3 Güvenlik Açıkları (Kodda)
- `vuln_scanner.py` içindeki URL'ler doğrulama yapılmadan doğrudan kullanılmaktadır. Sefa'nın `validators.py` modülü henüz sisteme entegre edilmemiştir.
- Exception handling bazı fonksiyonlarda yalnızca `except:` (bare except) kullanılmış, spesifik hata türleri yakalanmamaktadır.

---

## 7. Genel Değerlendirme

Proje, planlanan Scrum metodolojisine uygun ilerlemektedir. Her ekip üyesi kendi sorumluluğunu büyük ölçüde yerine getirmiştir. Dokümantasyon kalitesi genel olarak yüksektir.

Temel zorluk, modüllerin birbirinden bağımsız geliştirilmiş olması ve henüz tam anlamıyla entegre edilememiş olmasıdır. Özellikle veritabanı şeması, tarama motoru ve raporlama bileşenlerinin birleştirilmesi bir sonraki kritik adımdır.

Backend API (FastAPI) ve gerçek kullanıcı arayüzü (React.js) henüz başlanmamış olup projenin tamamlanması için öncelikli hedefler arasındadır.

---

*Bu rapor, Hafta 6 "Proje Toparlama ve Test Senaryoları Geliştirme" görevi kapsamında Nursena Karaduman tarafından hazırlanmıştır.*
