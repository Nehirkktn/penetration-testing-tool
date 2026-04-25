# Cyberscan: Özelleştirilebilir Test Senaryoları (Custom Scenarios) Mimari Raporu

**Hazırlayan:** MUHAMMED BAKİ BAŞBAY
**Proje:** Sızma Testi Otomasyon Aracı 

Bu doküman, Cyberscan otomasyon aracına kullanıcıların kendi özel sızma testi senaryolarını ekleyebilmesi, yönetebilmesi ve çalıştırabilmesi için planlanan mimari yapıyı ve sektör analizini detaylandırmaktadır.

## 1. Özellik Özeti ve Amacı
Standart tarama motorlarının (Nmap, SQLMap) ötesine geçerek, siber güvenlik uzmanlarının kendi "Özel Test Şablonlarını" sisteme entegre edebilmesi amaçlanmıştır. Bu özellik sayesinde Cyberscan; yeni çıkan (0-day) zafiyetlere karşı anında güncellenebilen, dışa açık ve dinamik bir tarama motoru haline gelecektir.

## 2. Mevcut Sızma Testi Araçlarındaki Yaklaşımlar
Özel senaryo mimarisi tasarlanmadan önce sektördeki standart araçlar incelenmiştir:
* **Nuclei (ProjectDiscovery):** Özelleştirilebilir şablon konusunda endüstri standardıdır. Tamamen **YAML** formatını kullanır. İnsan tarafından okunabilirliği çok yüksektir.
* **Metasploit Framework:** Genellikle **Ruby** tabanlı modüller kullanır. Çok güçlüdür ancak yeni bir senaryo eklemek ileri düzey programlama bilgisi gerektirir.
* **Burp Suite (BChecks):** Özel bir sözdizimi kullanır ve arka planda kural setleri çalıştırır.

**Sonuç:** Modern, hızlı ve kullanıcı dostu bir araç tasarladığımız için **Nuclei** mimarisi referans alınmış ve veri formatı olarak YAML seçilmiştir.

## 3. Format Seçimi: Neden YAML? (JSON Yerine)
Özel test senaryolarının saklanması ve yorumlanması için **YAML (.yaml)** formatı tercih edilmiştir. 
* **İnsan Odaklı Okunabilirlik:** JSON formatındaki karmaşık tırnak işaretleri, süslü parantezler ve virgüller yerine girintilere (indentation) dayalı temiz bir yapı sunar.
* **Hata Toleransı:** JSON'da unutulan tek bir virgül dosyanın bozulmasına yol açarken, YAML daha esnektir.
* **Yorum Satırı Desteği:** Güvenlik uzmanlarının senaryoların içine açıklayıcı notlar (`#`) eklemesine olanak tanır (JSON bu özelliği yerleşik olarak desteklemez).
* **Kolay Yorumlama:** Arka planda çalışan Python motoru, `PyYAML` kütüphanesi sayesinde bu dosyaları saniyeler içinde okuyup bir Python sözlüğüne (dictionary) çevirebilir.

## 4. Kullanıcı Deneyimi: Ekleme, Düzenleme ve Çalıştırma

Bu özelliğin Cyberscan sistemine entegrasyonu aşağıdaki akışla sağlanacaktır:

### A. Senaryo Yönetimi ve Saklama
* **Arayüz (UI):** Yönetim panelinde "Custom Scenarios" adında yeni bir modül açılacaktır. Kullanıcılar buraya ellerindeki `.yaml` dosyalarını yükleyebilecek (Upload) veya web tabanlı bir editör üzerinden doğrudan kendi kurallarını yazabileceklerdir.
* **Veritabanı (DB):** Veritabanına `CUSTOM_SCENARIOS` tablosu eklenecektir. Burada senaryonun meta verileri (`id`, `name`, `author`, `severity`, `file_path`) tutulacaktır. 
* **Dosya Sistemi:** Yüklenen `.yaml` dosyaları fiziksel olarak sunucuda (örneğin `/cyberscan/scenarios/`) güvenli bir şekilde saklanacaktır.

### B. Çalıştırma Akışı (Execution)
1. Kullanıcı "New Scan" (Yeni Tarama) başlattığında, Nmap/SQLMap gibi araçların yanında kendi özel senaryolarını da bir onay kutusu (checkbox) ile seçecektir.
2. Tarama tetiklendiğinde Python tabanlı **Özel Senaryo Motorumuz** devreye girecek ve seçilen `.yaml` dosyasını okuyacaktır.
3. Dosyada belirtilen dizinlere (path) HTTP istekleri atılacak, dönen yanıtlar (response status, body) senaryodaki "matchers" (eşleştiriciler) ile kıyaslanacaktır.
4. Eşleşme sağlanırsa, bulgu doğrudan `VULNERABILITIES` tablosuna loglanacaktır.

## 5. Örnek Senaryo Şablonu
Sistemimizin yorumlayacağı ve kullanıcıların baz alacağı örnek bir "Hassas Dosya İfşası (.env Leak)" senaryosu aşağıda verilmiştir:

```yaml
id: env-file-leak
info:
  name: ".env ve Config Dosyası Taraması"
  author: "MBB"
  severity: "High"
  description: "Sunucudaki açık .env veya config.php dosyalarını tespit eder."

requests:
  - method: GET
    path:
      - "{{target_url}}/.env"
      - "{{target_url}}/config.php"
    
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "DB_PASSWORD"
          - "APP_KEY"
        condition: or
