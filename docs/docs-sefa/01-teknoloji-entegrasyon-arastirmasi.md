# Sızma Testi Araçları Entegrasyon Araştırması ve Planlaması

> **Siber Savaşçılar** | Fırat Üniversitesi – Yazılım Mühendisliği Temelleri Projesi  
> **Hazırlayan:** Muhammet Sefa Kozan | **Hafta:** 2 | **Son Teslim:** 9 Nisan 2026

Bu doküman, Siber Savaşçılar sızma testi projesinin çatı mimarisine entegre edilecek temel güvenlik tarama teknolojilerinin (Nmap, Burp Suite, SQLMap, Metasploit) entegrasyon yöntemlerini, gerekli kütüphaneleri ve iletişim formatlarını tanımlar.

---

## 1. SQLMap Entegrasyonu (TAMAMLANDI ✅)

Projenin ilk modülü olan SQLMap başarıyla entegre edilmiştir. Uyguladığımız bu mimari, diğer araçlar için de referans olacaktır.

- **Entegrasyon Yöntemi:** Python `subprocess` kütüphanesi ile komut satırı tetiklemesi.
- **Veri Formatı:** Standart çıktı (STDOUT) üzerinden dönen düz metin, Regex (Düzenli İfadeler) kullanılarak `Vulnerability` ve `ScanResult` sınıflarına dönüştürülmektedir.
- **Kullanılan Araçlar:** Yerleşik `subprocess` ve `re (Regular Expressions)` modülleri. Başka bir dış kütüphane gerektirmez.
- **Veritabanı Uyumu:** Sonuçlar doğrudan SCANS, VULNERABILITIES ve REPORTS tablolarına uygun dict/JSON formatına çevrilir.

---

## 2. Nmap Entegrasyonu (Ağ Keşfi ve Port Tarama)

Nmap, ağdaki açık portları, servisleri ve işletim sistemlerini tespit etmek için kullanılacaktır.

- **Entegrasyon Yöntemleri:**
  1. **(Önerilen)** Nmap'in kendi XML çıktı formatını (`-oX`) kullanıp Python'un yerleşik `xml.etree.ElementTree` modülü ile okumak. Bu en güvenilir ve hızlı yöntemdir.
  2. Dış Kütüphane: `python-nmap` paketi. (Ancak bu kütüphane projenin bağımlılıklarını artıracaktır).
- **Hangi Veri Formatı Destekleniyor:** XML (Extensible Markup Language). Nmap, `-oX -` komutu ile sonucu doğrudan ekrana XML olarak basabilir.
- **Nasıl Yapılandırılır:** SQLMap modeline benzer bir `NmapConfig` nesnesi oluşturulacak (`target_ip`, `ports`, `scan_type: -sS, -sV` vb.).
- **Nasıl Test Edilecek:** 
  - Kendi yerel ağımızdaki `localhost` veya yasal olarak test edilebilir `scanme.nmap.org` adresi üzerinden.
  - Port verilerinin (Açık/Kapalı), çalışan servislerin (Apache, Nginx vb.) ve versiyon bilgilerinin veritabanındaki `ASSETS` veya `VÜLNERABILITIES` (eğer out-of-date servis varsa) tablosuna doğru işlenip işlenmediği kontrol edilecek.

---

## 3. Metasploit Framework (MSF) Entegrasyonu (Zafiyet İstismarı)

Metasploit, Nmap ve SQLMap gibi komut satırından tek atımlık ("one-shot") çalışmaktan ziyade, arka planda çalışan bir servis olarak tasarlanmıştır. Bu yüzden entegrasyon yöntemi farklılık gösterir.

- **Entegrasyon Yöntemi:** MSF RPC (Remote Procedure Call) API'si. Metasploit `msfrpcd` adında bir arka plan servisi çalıştırabilir. Python üzerinden bu servise kimlik doğrulaması yaparak komut gönderilir.
- **Gerekli Kütüphane:** `pymetasploit3` (Metasploit RPC'si ile Python arasındaki köprüyü kurar).
- **Hangi Veri Formatı Destekleniyor:** İstekler ve yanıtlar MessagePack / JSON mimarisiyle iletilir.
- **Nasıl Yapılandırılır:** 
  1. Sunucuda `msfrpcd -P şifre -n -f -a 127.0.0.1` komutu ile API ayağa kaldırılır.
  2. Python tarafında `MsfRpcClient` ile bağlanılıp, uygun exploit (ör: `exploit/unix/ftp/vsftpd_234_backdoor`) seçilir ve parametreleri (`RHOSTS`) atanarak tetiklenir.
- **Nasıl Test Edilecek:**
  - Zafiyetli sanal makineler (Metasploitable 2/3) Docker ile yerelde kurularak.
  - Sadece bilgi toplama (auxiliary) modülleri çalıştırılarak sistemin çökme riskini azaltan test senaryoları yazılacak.

---

## 4. Burp Suite API Entegrasyonu (Web Zafiyet Taraması)

Burp Suite Pro/Enterprise sürümleri güçlü bir REST API sunarken, Community sürümünde API desteği kısıtlıdır.

- **Entegrasyon Yöntemi:** Burp Suite Enterprise REST API. Belirli bir URL için tarama görevleri (Spidering & Auditing) HTTP istekleri ile başlatılır.
- **Gerekli Kütüphane:** Python'un standart `requests` kütüphanesi.
- **Hangi Veri Formatı Destekleniyor:** REST tabanlı JSON gönderilir (görev detayı) ve yanıtlar JSON formatında alınır.
- **Nasıl Yapılandırılır:**
  - API Key kullanılarak `http://localhost:1337/v0.1/scan` uç noktasına POST isteği atılarak tarama başlatılır.
  - Tarama süreci asenkron işler. Belli aralıklarla (örneğin 10 saniyede bir) GET isteği atılarak tarama durumu (% kaçı bitti) sorgulanır.
- **Nasıl Test Edilecek:**
  - OWASP Juice Shop veya `testphp.vulnweb.com` gibi zafiyetli hedefler kullanılarak.
  - Dönen JSON verisindeki `issue_name` ve `confidence` parametreleri, bizim `Vulnerability` (models/scan_result.py) sınıfımızla eşleştirilecek.

---

## 🛠️ Ortak Mimari Kararları ve Yansımaları

Bu araştırma sonucunda "Siber Savaşçılar" sızma testi aracının yapısının şöyle olması planlanmıştır:

1. **İki Farklı Çalıştırma Konsepti:**
   - **Komut Satırı Araçları (Subprocess tabanlı):** SQLMap ve Nmap. Python komutu yazar, çıktıyı yakalar.
   - **Servis/API Tabanlı Araçlar:** Metasploit (RPC) ve Burp Suite (REST API). Python sürekli iletişimde kalır ve durum sorgular.
2. **Merkezi Raporlama (Standardizasyon):**
   - Hangi araç çalışırsa çalışsın, parser'lar (ayrıştırıcılar) sonuçları `ScanResult` nesnelerine dönüştürmek zorundadır.
   - Böylece Nursena'nın veritabanı şeması ve web arayüzü, sonucun Metasploit'ten mi yoksa SQLMap'ten mi geldiğiyle ilgilenmez, sadece zafiyet tipi ve kritiklik puanıyla ilgilenir.

---

## ✅ Görev Gereksinimleri

Yukarıdaki araştırma ile birlikte **"Teknoloji Entegrasyon Araştırması"** görevinin istenen çıktıları elde edilmiştir:

| Gereksinim | Durum |
|---|---|
| Araçların API/Entegrasyon yöntemleri belirlendi (Subprocess, RPC, REST). | ✅  |
| Veri formatları incelendi (Regex Text, XML, Msgpack, JSON).| ✅ |
| Gerekli kütüphaneler saptandı (`xml.etree`, `pymetasploit3`, `requests`). | ✅ |
| Entegrasyonların nasıl test edilecekleri planlandı. | ✅ |
| Yasal ve güvenli test yöntemleri (Metasploitable, scanme.nmap vs.) planlandı. | ✅ |
