# SİBER SAVAŞÇILAR" - Proje Akışı ve Haftalık İlerleme

Bu dosya, "SİBER SAVAŞÇILAR" takımının haftalık proje ilerlemesini ve üyelerin görev dağılımlarını içermektedir.

## ## 1. Hafta (9-15 Mart) - Proje Başlatma ve Altyapı Hazırlığı

* **Nehir KÖKTEN (Yönetici):** GitHub üzerinde ana depo (repository) oluşturuldu ve ekip üyelerinin erişim yetkileri düzenlendi. Projenin dosya yapısı (kaynak kodlar için `src`, dökümanlar için `docs`) belirlendi ve ilk `README.md` dosyası ile projenin genel vizyonu sisteme girildi.
* **Muhammed Baki BAŞBAY:** Projenin yazılım dilleri ve kütüphane analizleri yapıldı. Tarama motoru için **Python** dilinin seçilmesine karar verildi; **python-nmap** ve **requests** kütüphanelerinin kurulum denemeleri yapılarak sürümler arası uyumluluk test edildi.
* **Şevval DURAN:** Geliştirme ve test süreçleri için sanal laboratuvar ortamı hazırlandı. Yerel makinede sızma testi araçlarının (**Nmap, SQLMap** vb.) hatasız çalışması için gerekli ortam değişkenleri (**Environment Variables**) yapılandırıldı.
* **M. Sefa KOZAN:** Proje takvimi oluşturuldu ve görevler **GitHub Projects** üzerinden kategorize edildi. Ekip üyelerinin haftalık ilerlemelerini raporlayabileceği bir iş akış şeması tasarlandı.
* **Nursena KARADUMAN:** Proje kapsamında taranacak olan zafiyetlerin listesi çıkarıldı. Özellikle **SQL Injection** ve Port tarama süreçlerinde hangi parametrelerin (zayıf şifreler, açık portlar vb.) hedefleneceği teknik olarak dökümante edildi.

---

## ## 3. Hafta (23-29 Mart) - Mimari Tasarım ve Veri Modelleme

* **Nehir KÖKTEN (Yönetici):** Projenin modüler mimari tasarımı yapıldı. Sistemin ana motoru ile raporlama biriminin birbirini engellemeden çalışması için "**Katmanlı Mimari**" (**Layered Architecture**) yapısı kurgulandı ve bileşenler arası veri akış yolları diyagram üzerinde gösterildi.
* **Nursena KARADUMAN:** Tarama sonuçlarının kaydedileceği veritabanı şeması (**ER Diyagramı**) hazırlandı. Verilerin düzenli tutulması için tablolar arası ilişkiler (**Primary Key, Foreign Key**) kuruldu ve veritabanı normalizasyonu yapılarak veri tekrarının önüne geçildi.
* **Muhammed Baki BAŞBAY:** Kullanıcı arayüzü (**UI**) için arayüz taslakları (**Wireframe**) çizildi. Kullanıcının tarama başlatabileceği, canlı olarak süreci izleyebileceği ve tarama bitince **PDF** raporu alabileceği ekranların tasarımı ve buton yerleşimleri planlandı.
