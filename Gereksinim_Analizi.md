# 🛡️ SİBER SAVAŞÇILAR | ANALİZ RAPORU
---

> **PROJE YÖNETİCİSİ:** `Nehir Kökten`  

> **TARİH:** `07.03.2026`

---

<br>

## 📋 1. DOKÜMAN AMACI VE KAPSAMI

Bu rapor, **"Siber Savaşçılar"** projesinin teknik sınırlarını belirlemek ve projeden etkilenen paydaşların beklentilerini analiz etmek amacıyla oluşturulmuştur. 

Projenin ana hedefi; manuel sızma testi süreçlerini otomatize ederek siber güvenlik uzmanlarına ve sistem yöneticilerine hızlı, güvenilir ve eyleme dönüştürülebilir veriler sunmaktır.

<br>

---

## ⚙️ 2. GEREKSİNİM ANALİZİ (REQUIREMENTS)

### 2.1. Fonksiyonel Gereksinimler
*Sistemin kullanıcıya sunması gereken temel işlevsel yetenekler:*

* **[FR-01] Otomatik Varlık Keşfi** Belirlenen ağ aralığında aktif cihazları, açık portları ve çalışan servisleri tespit edebilmeli.

* **[FR-02] Zafiyet Tanımlama** Hedef servislerdeki bilinen açıkları (CVE taraması) ve web tabanlı zafiyetleri (SQLi, XSS) otomatik olarak tarayabilmeli.

* **[FR-03] Doğrulama (Exploitation)** Tespit edilen zayıf noktaların "yanlış alarm" (false positive) olmadığını güvenli test senaryolarıyla doğrulamalı.

* **[FR-04] Rapor Üretimi** Bulguları risk skorlarına (CVSS) göre önceliklendirmeli ve çözüm önerilerini içeren PDF/HTML raporlar oluşturmalı.

<br>

### 2.2. Teknik Gereksinimler
*Sistemin altyapısal ve operasyonel standartları:*

* **[TR-01] Yazılım Dili** Geliştirme sürecinde **Python 3.10+** ve ilgili siber güvenlik kütüphaneleri kullanılacaktır.

* **[TR-02] Modüler Mimari** Yeni saldırı imzalarının ve test modüllerinin kolayca eklenebileceği esnek bir yapı kurulacaktır.

* **[TR-03] Güvenli Depolama** Tarama verileri ve hedef sistem bilgileri **AES-256** standardında şifrelenerek saklanacaktır.

* **[TR-04] Entegrasyon** Nmap, Metasploit RPC ve SQLMap gibi endüstri standardı araçlarla tam uyumlu çalışacaktır.

<br>

---

## 👥 3. PAYDAŞ ANALİZİ VE BEKLENTİ YÖNETİMİ

| Paydaş Grubu | Tanımı ve Rolü | Temel Beklentileri |
| :--- | :--- | :--- |
| **Sistem Yöneticileri (IT)** | Test edilen altyapının sahipleri. | Aracın sistem üzerinde kesinti (DoS) yaratmaması ve stabil çalışması. |
| **Siber Güvenlik Analistleri** | Aracı kullanacak olan uzmanlar. | Hızlı sonuç üretimi, düşük hatalı pozitif oranı ve teknik derinliği olan raporlar. |
| **Denetim Birimleri** | KVKK, GDPR ve ISO 27001 ekipleri. | Tarama sonuçlarının yasal standartlara uygun formatta sunulması. |
| **Ders Sorumlusu (Hoca)** | Değerlendirme ve Onay Makamı. | Teknik yeterlilik, dökümantasyon kalitesi ve Scrum metodolojisine uyum. |
| **Kurumsal Yöneticiler** | Güvenlik yatırımlarını yöneten birimler. | Mevcut risk durumunu bir "Güvenlik Skoru" olarak net bir şekilde görebilme. |

<br>

---

## 🎯 4. BAŞARI METRİKLERİ VE KISITLAMALAR 

* **KPI (Başarı Göstergesi):** Geliştirilen aracın, standart bir lab ortamında en az **%90 doğruluk oranıyla** zafiyet tespit edebilmesi.

* **Hukuki Kısıtlama:** Yazılımın "Etik Hacking" sınırları içerisinde kalması için kullanıcıdan tarama öncesi **dijital onay** alınması zorunludur.

* **Performans Hedefi:** Normalde Manuel yapılan bir bilgi toplama sürecini her zamankinden daha az bir sürede tamamlamak.

* **Operasyonel Risk:** Yoğun taramaların ağ trafiğinde oluşturabileceği yükü minimize etmek için "Hız Ayarı" mekanizması eklenecektir.

<br>

---

<p align="right">
  <i>Hazırlayan: <b>Nehir Kökten</b> - Siber Savaşçılar Proje Yöneticisi</i>
</p>
