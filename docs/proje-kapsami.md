# Siber Savaşçılar: Otomatize Sızma Testi ve Zafiyet Analiz Platformu
## Proje Analizi ve Kapsam Belirleme Raporu

---------------------------------------------------------------------------

### 1. Projenin Amacı ve Hedefleri
**Siber Savaşçılar** ekibi olarak geliştirdiğimiz bu projenin temel vizyonu, web uygulamalarındaki güvenlik açıklarını manuel müdahale gerektirmeden, otomatize bir şekilde tespit etmektir.

**Stratejik Hedeflerimiz:**
* **Genel Amaç:** Web ekosistemindeki güvenlik açıklarını tespit eden güvenilir ve hızlı bir otomasyon motoru oluşturmak.
* **Geliştirici Desteği:** Yazılım geliştiricilere, kodlarını canlı ortama (production) almadan önce hızlı bir güvenlik taraması sunarak proaktif koruma sağlamak.
* **Maliyet ve Zaman Optimizasyonu:** Siber güvenlik denetim süreçlerinde harcanan zaman maliyetini ve insan kaynağı yükünü minimize etmek.

---------------------------------------------------------------------------

### 2. Kapsam Dahilindeki Zafiyetler (OWASP Top 10 Odaklı)

**OWASP Top 10 Güvenlik Riskleri Analizi**
Bu proje kapsamında web uygulamalarında en sık karşılaşılan güvenlik açıklarını analiz etmek amacıyla **OWASP Top 10 (2021)** güvenlik riskleri referans alınmıştır. OWASP Top 10, dünya genelinde web uygulamalarında en yaygın olarak karşılaşılan kritik güvenlik açıklarını belirleyen bir standarttır. Aşağıda bu risk kategorileri ve örnek saldırı senaryoları özetlenmiştir.

#### **A01: Broken Access Control (Bozuk Erişim Kontrolü)**
Bozuk erişim kontrolü, kullanıcıların yetkileri dışında bulunan verilere veya sistem işlevlerine erişebilmesi durumunu ifade eder. Bu tür güvenlik açıkları genellikle uygulama içinde yeterli yetkilendirme kontrollerinin yapılmamasından kaynaklanır.

**Örnek Senaryolar:**
* Bir web uygulamasında kullanıcı hesap bilgileri URL parametresi ile belirlenmektedir. Saldırgan, URL’de bulunan hesap numarasını değiştirerek başka kullanıcıların hesap bilgilerine erişebilmektedir.
  * **Örnek:** `https://example.com/app/accountInfo?acct=notmyacct`
* Yönetici paneline erişim için gerekli yetki kontrolü yalnızca kullanıcı arayüzünde yapılmaktadır. Ancak saldırgan doğrudan ilgili URL adresine istek göndererek yönetici fonksiyonlarına erişebilmektedir.
  * **Örnek:** `https://example.com/app/admin_getappInfo`

#### **A02: Cryptographic Failures (Kriptografik Hatalar)**
Kriptografik hatalar, hassas verilerin yeterli şekilde korunmaması veya uygun şifreleme yöntemlerinin kullanılmaması sonucunda ortaya çıkan güvenlik açıklarını ifade eder.

**Örnek Senaryolar:**
* Kullanıcı şifrelerinin veritabanında şifrelenmeden saklanması ve veritabanı sızıntısı durumunda tüm kullanıcı bilgilerine erişilebilmesi.
* Kullanıcıların kişisel bilgilerinin HTTP üzerinden iletilmesi nedeniyle ağ üzerindeki saldırganların bu verileri ele geçirebilmesi.

#### **A03: Injection (Enjeksiyon)**
Enjeksiyon saldırıları, uygulamanın kullanıcıdan aldığı verileri doğrulamadan doğrudan sistem komutlarına veya veritabanı sorgularına dahil etmesi sonucunda ortaya çıkar.

**Örnek Senaryolar:**
* **SQL Injection:** Saldırganın veritabanı sorgularını manipüle ederek hassas verilere erişebilmesi.
* **Cross-Site Scripting (XSS):** Web sayfasına zararlı JavaScript kodu eklenmesi ve kullanıcı oturum bilgilerinin ele geçirilmesi.

#### **A04: Insecure Design (Güvensiz Tasarım)**
Güvensiz tasarım, yazılımın mimarisinin güvenlik prensipleri dikkate alınmadan oluşturulması sonucu ortaya çıkan sistematik güvenlik zafiyetlerini ifade eder.

**Örnek Senaryolar:**
* Kullanıcı giriş sistemi için başarısız giriş denemelerine herhangi bir sınırlama uygulanmaması.
* Kritik işlemler için ek doğrulama mekanizmalarının bulunmaması.

#### **A05: Security Misconfiguration (Hatalı Güvenlik Yapılandırması)**
Bu kategori, sistem veya uygulama yapılandırmasının yanlış yapılması veya varsayılan ayarların değiştirilmemesi sonucunda ortaya çıkan güvenlik risklerini kapsar.

**Örnek Senaryolar:**
* Sunucu hata mesajlarının sistem yapılandırması ve veritabanı bilgileri gibi hassas detayları içermesi.
* Yönetici hesabının varsayılan kullanıcı adı ve şifre ile bırakılması.

#### **A06: Vulnerable and Outdated Components (Savunmasız ve Güncel Olmayan Bileşenler)**
Bu risk kategorisi, projede kullanılan yazılım bileşenlerinin güncel olmaması veya bilinen güvenlik açıkları içermesi durumunda ortaya çıkar.

**Örnek Senaryolar:**
* Güvenlik açığı bulunan eski bir JavaScript kütüphanesinin projede kullanılmaya devam edilmesi.
* Güncelleme desteği sona ermiş bir framework sürümünün kullanılması.

#### **A07: Identification and Authentication Failures (Kimlik Doğrulama Hataları)**
Bu kategori, kullanıcı kimliğinin doğrulanması ve oturum yönetimi süreçlerindeki zayıflıkları ifade eder.

**Örnek Senaryolar:**
* Kullanıcıların çok zayıf parolalar kullanmasına izin verilmesi.
* Oturum kimliklerinin tahmin edilebilir veya tekrar kullanılabilir olması.

#### **A08: Software and Data Integrity Failures (Yazılım ve Veri Bütünlüğü Hataları)**
Bu risk, yazılım güncellemelerinin veya sistem bileşenlerinin doğruluğu kontrol edilmeden sisteme kabul edilmesi durumunda ortaya çıkar.

**Örnek Senaryolar:**
* Yazılım güncellemelerinin dijital imza doğrulaması yapılmadan kurulması.
* Üçüncü parti paketlerin güvenilirliği kontrol edilmeden projeye eklenmesi.

#### **A09: Security Logging and Monitoring Failures (Güvenlik Günlüğü ve İzleme Hataları)**
Bu kategori, sistemde gerçekleşen güvenlik olaylarının yeterli şekilde kayıt altına alınmaması veya izlenmemesi sonucunda ortaya çıkan riskleri kapsar.

**Örnek Senaryolar:**
* Başarısız giriş denemelerinin sistem loglarına kaydedilmemesi.
* Şüpheli aktiviteleri tespit edecek izleme mekanizmalarının bulunmaması.

#### **A10: Server-Side Request Forgery (SSRF)**
SSRF saldırıları, saldırganın sunucuyu kendi belirlediği bir adrese istek göndermeye zorlaması sonucu ortaya çıkar.

**Örnek Senaryolar:**
* Sunucunun kullanıcı tarafından verilen bir URL üzerinden iç ağdaki servislere erişim sağlaması.
* Uygulamanın dış kaynaklardan veri çekerken URL doğrulaması yapmaması.

> **Önemli Not:** Yukarıda analiz edilen OWASP Top 10 listesi projemizin teorik çerçevesini oluşturmaktadır. Geliştirme sürecinde, otomatize edilmeye ve Python kütüphaneleriyle (Requests, BeautifulSoup) tespite en uygun olan **A01 (Erişim Kontrolü)**, **A03 (Enjeksiyon)** ve **A05 (Hatalı Yapılandırma)** maddeleri öncelikli olarak kodlanacaktır.

---------------------------------------------------------------------------

### 3. Teknik Sınırlar (Kapsam Dışı)
Projemizin teknik odağını korumak ve hedefe odaklanmak amacıyla belirli alanlar kapsam dışı bırakılmıştır:
* **Kapsam Dışı:** Sosyal mühendislik saldırıları, fiziksel sızma testleri, DDoS saldırıları ve mobil uygulama taramaları bu projenin dışındadır.
* **Sınırlamalar:** Geliştirilen araç sadece **HTTP/HTTPS** protokolleri üzerinden erişilebilen web arayüzlerini ve servislerini tarayacaktır.

---------------------------------------------------------------------------

### 4. Kullanılacak Teknolojiler ve Kütüphaneler
Projemiz, modern siber güvenlik ihtiyaçlarına hızlı yanıt verebilmek adına şu teknoloji yığınıını kullanmaktadır:
* **Dil:** **Python** (Yüksek seviyeli kütüphane desteği, hızlı prototipleme kabiliyeti ve siber güvenlik topluluğu desteği nedeniyle tercih edilmiştir).
* **Temel Kütüphaneler:**
    * `Requests`: HTTP trafiğini yönetmek ve sunucu yanıtlarını analiz etmek için.
    * `BeautifulSoup`: HTML doküman yapısını parse ederek açık barındıran tag'leri aramak için.
    * `python-nmap`: Ağ katmanında açık portları ve çalışan servisleri tespit etmek için.

---------------------------------------------------------------------------

### 5. Başarı Kriterleri ve Performans Göstergeleri
Projenin başarıyla tamamlandığını kabul etmek için aşağıdaki kriterler temel alınacaktır:
* Belirlenen öncelikli OWASP açıklarının en az **%80 doğruluk oranıyla** tespit edilmesi.
* Tarama işlemi sonucunda, son kullanıcıya zafiyetin türünü ve çözüm önerisini içeren anlaşılır bir **"Zafiyet Analiz Raporu"** sunulması.

---

### Kaynakça
* **OWASP Foundation (2021).** *OWASP Top 10:2021 – The Ten Most Critical Web Application Security Risks.* Erişim adresi: [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
