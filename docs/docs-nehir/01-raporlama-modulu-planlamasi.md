# Güvenlik Açığı Raporlama Modülü Planlama Dokümanı

## 1.Modülün Amacı
Bu modül, arka planda çalışan sızma testi araçlarının (Nmap, SQLMap, Burp Suite vb.) elde ettiği ham verileri (logları) kullanıcıların ve sistem yöneticilerinin kolayca anlayabileceği, yapılandırılmış ve profesyonel belgelere dönüştürmekle görevlidir.

## 2. Rapor Çıktı Formatları
Sistemin farklı kullanıcı profillerine hitap edebilmesi için raporlar 3 farklı formatta oluşturulacaktır:
* **HTML Rapor:** Kullanıcının web arayüzü (dashboard) üzerinden tarama biter bitmez sonuçları interaktif ve renkli bir şekilde görebilmesi içindir.
* **PDF Rapor:** Üst yönetime veya müşterilere sunulmak üzere, resmi belge formatında, değiştirilemez ve yazdırılabilir formattır (Yönetici Özeti içerir).
* **CSV / JSON Formatı:** Geliştiricilerin veya siber güvenlik uzmanlarının, bulunan zafiyet verilerini başka yazılımlara (örn: SIEM sistemleri) kolayca aktarabilmesi içindir.

## 3. Raporda Yer Alacak Veri Yapısı (İçerik)
Her bir rapor, standart bir sızma testi raporu formatında olacak ve şu bilgileri içerecektir:

### A. Yönetici Özeti (Executive Summary)
* Tarama Tarihi ve Saati
* Hedef Sistem (IP veya Domain)
* Tespit Edilen Toplam Zafiyet Sayısı
* Risk Dağılım Grafiği (Örn: 2 Kritik, 5 Orta, 1 Düşük)

### B. Zafiyet Detayları (Her bir açık için)
* **Zafiyet Tanımı:** Açığın adı (Örn: SQL Injection, Cross-Site Scripting).
* **Risk Seviyesi:** Renk kodlu uyarı sistemi (Kritik - Kırmızı, Yüksek - Turuncu, Orta - Sarı, Düşük - Mavi).
* **Etkilenen Hedef:** Açığın bulunduğu tam URL veya Port numarası.
* **Kanıt (Proof of Concept - PoC):** Sistemin zafiyeti nasıl bulduğuna dair kısa log veya payload gösterimi.
* **Çözüm Önerisi (Remediation):** Yazılımcıların bu açığı nasıl kapatabileceğine dair çözüm adımları (Örn: "Parametreli SQL sorguları kullanın").

## 4. Kullanıcı Arayüzü (UI) Tasarım Planı
Arayüzde bu modülün kullanımı şu şekilde planlanmıştır:
1. Yan menüde (Sidebar) **"Geçmiş Taramalar ve Raporlar"** sekmesi bulunacak.
2. Kullanıcı bu sekmeye girdiğinde, önceki taramaları bir tablo halinde görecek.
3. Tablonun sağ kısmında her tarama için **"Raporu Görüntüle (HTML)"** ve **"İndir (PDF | CSV)"** butonları yer alacak.

## 5. Diğer Bileşenlerle Entegrasyon (Sistem Akışı)
* **Veritabanı Entegrasyonu:** Raporlama modülü, oluşturacağı belgenin içeriklerini doğrudan **Veri Katmanından (SQLite)** `SELECT` sorguları ile çekecektir.
* **Tarama Motoru (Backend) Entegrasyonu:** Orkestratör modülü Nmap ve web tarama işlemlerini bitirip veritabanına kaydettiği anda, otomatik olarak Raporlama modülüne bir sinyal (tetikleme) gönderecek ve rapor oluşturma süreci başlayacaktır.
* **UI Entegrasyonu:** Rapor oluşturulduğunda Sunum Katmanına bir bildirim gönderilecek ve kullanıcının ekranında "Raporunuz Hazır" uyarısı belirecektir.
