# Siber Savaşçılar: Veritabanı Mimari Tasarımı
## Proje Veri Modeli ve İlişkisel Şeması

----------------------------------------------------------------------------------------------------------------------------

### 1. Veritabanı Seçimi
Projemizin geliştirme aşamasında **SQLite** kullanılması kararlaştırılmıştır. Sunucu kurulumu gerektirmemesi ve Python ile yerleşik uyumu sayesinde hızlı prototipleme imkanı sağlar.

----------------------------------------------------------------------------------------------------------------------------

### 2. Tablo Yapıları ve Veri Tipleri

Sistemimiz toplamda 5 ana tablo üzerinden yönetilecektir:

#### **A. USERS (Kullanıcılar)**
* `id` (PK): Benzersiz kullanıcı numarası.
* `username`: Kullanıcı adı.
* `email`: E-posta adresi.
* `password_hash`: Şifrenin güvenli hali.
* `role`: Kullanıcı yetkisi (Admin/User).

#### **B. SCAN_CONFIGS (Tarama Yapılandırmaları)**
Kullanıcının özelleştirilmiş tarama ayarlarını tutar.
* `id` (PK): Yapılandırma ID.
* `user_id` (FK): Ayarı oluşturan kullanıcı.
* `check_sqli`: SQL Injection taransın mı? (Boolean).
* `check_xss`: XSS taransın mı? (Boolean).
* `check_misconfig`: Hatalı yapılandırma taransın mı? (Boolean).

#### **C. SCANS (Taramalar)**
* `id` (PK): Tarama numarası.
* `user_id` (FK): Taramayı yapan kullanıcı.
* `target_url`: Hedef web sitesi.
* `status`: Durum (Başladı/Bitti/Hata).
* `started_at / finished_at`: Zaman damgaları.

#### **D. VULNERABILITIES (Zafiyetler)**
* `id` (PK): Zafiyet ID.
* `scan_id` (FK): Hangi taramaya ait olduğu.
* `vuln_type`: Açık türü (SQLi, XSS vb.).
* `severity`: Kritiklik seviyesi.

#### **E. REPORTS (Raporlar)**
* `id` (PK): Rapor ID.
* `scan_id` (FK): İlgili tarama.
* `summary`: Tarama sonuç özeti.

----------------------------------------------------------------------------------------------------------------------------

### 3. İlişkisel Mantık (ER Özeti)
* **Kullanıcılar**, birden fazla **Tarama** başlatabilir ve kendi **Tarama Ayarlarını** oluşturabilir.
* Her **Tarama**, seçilen bir **Yapılandırmaya** göre çalışır.
* **Taramalar** sonucunda sıfır veya daha fazla **Zafiyet** bulunabilir ve her tarama bir **Rapor** üretir.
