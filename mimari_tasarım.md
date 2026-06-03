# "SİBER SAVAŞÇILAR" - Sistem Mimarisi ve Tasarım Dokümanı

## 1. Projenin Amacı ve Kapsamı
Bu proje, manuel sızma testi (penetration testing) süreçlerini hızlandırmak ve standartlaştırmak amacıyla geliştirilen Python tabanlı bir otomasyon aracıdır. Sistem; ağ keşfi (Nmap), zafiyet tarama (SQLMap, Burp Suite API) ve doğrulama (Metasploit) araçlarını tek bir merkezden yöneterek, elde edilen bulguları anlaşılır bir rapor halinde son kullanıcıya sunmayı hedefler.

## 2. Mimari Yaklaşım (3-Katmanlı Mimari)
Projemiz, kodun yönetilebilirliğini ve modülerliğini sağlamak amacıyla 3 temel katman (3-Tier) üzerinden tasarlanmıştır.

### 2.1. Sunum Katmanı (Arayüz - Frontend)
Kullanıcının sistemle etkileşime girdiği bölümdür. 
* **Teknoloji:** HTML, CSS, JavaScript (veya Python tabanlı basit bir arayüz kütüphanesi).
* **İşlevi:** Kullanıcıdan "Hedef IP/URL" bilgisini alır, tarama seviyesini (Hızlı, Kapsamlı vb.) seçtirir ve arka planda çalışan motorun (Backend) ürettiği sonuçları görselleştirir (Dashboard).

### 2.2. İş Mantığı Katmanı (Tarama Motoru - Backend)
Sistemin ana yönetim merkezidir. Dış araçların çalıştırılması ve verilerin işlenmesi burada gerçekleşir.
* **Teknoloji:** Python (Temel dil). Nmap ve diğer konsol araçlarını çalıştırmak için Python'un `subprocess` ve `os` kütüphanelerinden faydalanılacaktır.
* **Ana Modüller:**
  * **Orkestratör (Main Controller):** Kullanıcıdan gelen isteği alır ve tarama sırasını belirler.
  * **Keşif (Recon) Modülü:** Hedef sisteme Nmap taraması başlatır, açık portları ve servis versiyonlarını tespit eder. Çıktıları ayrıştırır (parsing).
  * **Zafiyet Tarama Modülü:** Keşif modülünden gelen verilere göre, örneğin 80. portta bir web sunucusu varsa SQLMap veya Burp Suite API'sini tetikler.
  * **Raporlama Modülü:** Toplanan ham verileri (logları) analiz eder ve PDF/HTML formatında son kullanıcı raporu (Executive Summary) oluşturur.

### 2.3. Veri Katmanı (Database)
Tarama geçmişinin ve tespit edilen zafiyetlerin kalıcı olarak saklandığı bölümdür.
* **Teknoloji:** Kurulum kolaylığı ve gömülü yapısı nedeniyle **SQLite** (veya MySQL) kullanılacaktır.
* **Saklanacak Temel Veriler:** Tarama tarihleri, hedef IP adresleri, tespit edilen açıkların CVSS (Ortak Zafiyet Değerlendirme Sistemi) puanları ve çözüm önerileri.

## 3. Sistem Veri Akışı (Data Flow)
Bir tarama işleminin yaşam döngüsü aşağıdaki adımlardan oluşur:

1. **Girdi:** Kullanıcı web arayüzüne hedef IP'yi (Örn: `192.168.1.50`) girer ve "Tara" komutunu yollar.
2. **Keşif (Aşama 1):** Python Orkestratörü, arka planda `nmap -sV 192.168.1.50` komutunu çalıştırır. Dönüş yapan terminal loglarını yakalar ve içindeki açık portları filtreler.
3. **Karar Mekanizması:** Eğer web portları (80, 443) açıksa, sistem otomatik olarak web zafiyet tarayıcılarını (SQLMap) o hedefe yönlendirir.
4. **Veritabanı Kaydı:** Bulunan her zafiyet (Örn: XSS açığı) SQL veritabanına bir satır olarak anlık kaydedilir.
5. **Çıktı:** Tarama bittiğinde, Veritabanındaki tüm bulgular çekilir, Raporlama Modülüne iletilir ve kullanıcıya sunulur.

## 4. Hata Yönetimi ve Güvenlik (Exception Handling)
* Tarama esnasında hedef sistemin çökmesi veya Nmap'in yanıt vermemesi gibi durumlarda, araç hata verip kapanmayacak (Crash); "Try-Catch/Except" blokları ile hata loglanıp sıradaki işleme geçilecektir.
* Sistemin kendi güvenliği için, kullanıcıdan alınan URL veya IP adresleri, doğrudan komut satırına iletilmeden önce güvenlik süzgecinden (Input Validation) geçirilecektir.
