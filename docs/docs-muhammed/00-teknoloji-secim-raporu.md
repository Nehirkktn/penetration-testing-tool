**Hazırlayan :** MUHAMMED BAKİ BAŞBAY
**Proje:** Sızma Testi Otomasyon Aracı

# Teknoloji Araştırma ve Seçim Raporu



## 1. Proje Özeti ve Amacı
Bu rapor, "Sızma Testi Otomasyon Aracı" projesinde kullanılacak teknolojilerin analizini ve seçimini içermektedir. Hedefimiz; web uygulamaları ve ağ sistemleri için otomatik zafiyet taraması, güvenlik açığı analizi ve OWASP standartlarına uygun raporlama yapabilen, yönetilebilir bir sistem inşa etmektir.

## 2. Ana Programlama Dili

Zafiyet tarama motorunun ve araç entegrasyonlarının geliştirilmesi için değerlendirilen diller:

| Teknoloji | Avantajlar | Dezavantajlar | Karar |
| :--- | :--- | :--- | :--- |
| **Python** | Proje gereksinimi olan siber güvenlik araçlarıyla (Nmap, SQLMap, Metasploit) en yüksek uyumluluğa ve zengin kütüphane desteğine sahip dildir. | C/C++ veya Go gibi dillere kıyasla çalışma zamanında daha yavaştır. | **Seçildi.** Araç entegrasyonu ve otomasyon kolaylığı nedeniyle sistemin ana dili olarak belirlendi. |
| **Go (Golang)** | Yüksek performans ve asenkron (goroutine) ağ taramaları için mükemmel kaynak yönetimi sağlar. | Güvenlik araçlarıyla entegrasyon için Python kadar hazır kütüphane sunmaz, sıfırdan yazım gerektirir. | Elendi. |

## 3. Güvenlik ve Zafiyet Tarama Araçları (Core Engine)

Otomatik zafiyet tarama motoruna entegre edilecek temel araçların analizi:

| Araç | Kullanım Amacı | Avantajlar | Dezavantajlar | Karar |
| :--- | :--- | :--- | :--- | :--- |
| **Nmap** | Ağ keşfi, açık port ve servis taraması. | Endüstri standardıdır. Hızlıdır ve Scripting Engine (NSE) ile genişletilebilir. | Doğrudan web uygulaması zafiyetlerine (XSS, SQLi vb.) odaklanmaz. | **Seçildi.** |
| **SQLMap** | SQL Injection zafiyetlerinin tespiti. | Veritabanı sızma testlerinde en kapsamlı araçtır. Otomatize edilebilir. | Sadece veritabanı odaklıdır. Agresif taramalar sistemleri yorabilir. | **Seçildi.** |
| **Burp Suite API** | OWASP standartlarında web uygulaması güvenlik testi. | Web zafiyetlerini bulmada en gelişmiş, derinlemesine analiz yapan motordur. | API ve tam otomasyon özellikleri genellikle ücretli sürümlerde bulunur. | **Seçildi.** |
| **Metasploit** | Zafiyet doğrulama ve sömürü (Exploitation). | Devasa exploit veritabanına sahiptir. MSF RPC üzerinden yönetilebilir. | Sisteme ağır bir yük bindirebilir ve API entegrasyon mimarisi karmaşıktır. | **Seçildi.** |

## 4. Web Tabanlı Yönetim Paneli

Kullanıcıların özelleştirilebilir test senaryolarını yönetecekleri arayüz altyapısı:

### Backend (Sunucu Tarafı)
| Teknoloji | Avantajlar | Dezavantajlar | Karar |
| :--- | :--- | :--- | :--- |
| **FastAPI (Python)** | Çok yüksek performans, yerleşik asenkron (async) desteği, otomatik Swagger dokümantasyonu. | Django'ya göre dahili admin paneli gibi hazır modüller sunmaz. | **Seçildi.** Tarama işlemlerinin asenkron yürütülmesi kritik olduğu için tercih edildi. |
| **Django (Python)** | Hazır admin paneli, güçlü ORM ve yüksek güvenlik sağlar. | Sadece API odaklı ve mikroservis tarzı asenkron mimariler için hantal kalabilir. | Elendi. |

### Frontend (İstemci Tarafı)
| Teknoloji | Avantajlar | Dezavantajlar | Karar |
| :--- | :--- | :--- | :--- |
| **React.js** | Dinamik raporların ve anlık tarama durumlarının ekranda gösterilmesi için yüksek performanslıdır. | Öğrenme eğrisi ve state yönetimi başlangıçta karmaşık olabilir. | **Seçildi.** Web tabanlı modern yönetim paneli için idealdir. |

## 5. Görev Yönetimi ve Asenkron İşlemler (Kritik Mimari)

Sızma testleri uzun süren işlemlerdir. Web panelinin kilitlenmesini önlemek için gereken mimari:

| Teknoloji | Kullanım Amacı ve Karar Nedeni | Karar |
| :--- | :--- | :--- |
| **Celery + Redis** | Kullanıcı paneli üzerinden tarama başlattığında, görev Celery'ye iletilir ve arka planda işlenir. Bu sayede yönetim paneli donmaz ve eşzamanlı birden fazla test senaryosu çalıştırılabilir. | **Seçildi.** |

## 6. Veritabanı ve Raporlama Modülü

| Teknoloji | Kullanım Amacı ve Avantajı | Karar |
| :--- | :--- | :--- |
| **PostgreSQL** | Bulunan zafiyetleri, tarama geçmişini ve kullanıcı loglarını güvenle saklamak için güçlü ilişkisel veritabanı. | **Seçildi.** |
| **Jinja2 + pdfkit** | Veritabanındaki zafiyet sonuçlarını OWASP formatındaki HTML şablonlarına yerleştirip profesyonel PDF raporlarına dönüştürmek için kullanılacaktır. | **Seçildi.** |

## 🎯 Nihai Proje Teknoloji Yığını (Tech Stack)

Sistem gereksinimlerine göre Sızma Testi Otomasyon Aracı için seçilen kesinleşmiş teknolojiler şunlardır:

1. **Geliştirme Dili:** Python 3.x
2. **Güvenlik Araçları:** Nmap, SQLMap, Metasploit, Burp Suite (API)
3. **Web API & Backend:** FastAPI
4. **Web Arayüzü:** React.js
5. **Arka Plan Görev Yöneticisi:** Celery & Redis
6. **Veritabanı:** PostgreSQL
7. **Raporlama Çıktısı:** JSON ve PDF (pdfkit)
