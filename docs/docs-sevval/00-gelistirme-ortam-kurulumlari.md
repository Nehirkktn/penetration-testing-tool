# Sızma Testi Otomasyon Aracı
## Geliştirme Ortamı Kurulumu ve Yapılandırma Dokümantasyonu

### 1. Proje Tanımı
Bu doküman, **Sızma Testi Otomasyon Aracı** projesi için geliştirme ortamının kurulum ve yapılandırma adımlarını içerir. Araç, web uygulamaları ve ağ sistemleri üzerinde otomatik sızma testleri gerçekleştirecek, zafiyet taraması ve raporlama modüllerini içerecektir. Proje OWASP standartlarına uygun test senaryoları ile desteklenecektir.

Projenin geliştirme sürecinde kullanılacak ana teknolojiler:
- Python (ana geliştirme dili)
- Nmap (port ve ağ taraması)
- Burp Suite API (web uygulaması güvenlik testleri)
- SQLMap (SQL Injection testi)
- Metasploit Framework (güvenlik açığı doğrulama)

---

### 2. Sistem Gereksinimleri
- İşletim Sistemi: Linux (Kali Linux / Ubuntu önerilir) veya Windows
- RAM: Minimum 8 GB
- Disk Alanı: Minimum 20 GB boş alan
- Python 3.9 veya üzeri

---

### 3. Geliştirme Ortamı Kurulumu

#### 3.1 Python Kurulumu
Python, projenin temel geliştirme dili olarak kullanılacaktır.

Kurulum:
1. https://www.python.org/downloads/ adresinden Python indirildi.
2. Kurulum sırasında **Add Python to PATH** seçeneği işaretlendi.

Kurulum doğrulama:
```bash
python --version
```

Gerekli kütüphaneler:
```bash
pip install flask requests python-nmap sqlalchemy
```

#### 3.2 Nmap Kurulumu
Nmap ile ağ keşfi ve port taraması yapılacaktır.

Linux:
```bash
sudo apt update
sudo apt install nmap
```

Windows:
https://nmap.org/download.html

Doğrulama:
```bash
nmap --version
```

#### 3.3 SQLMap Kurulumu
SQLMap ile otomatik SQL Injection testleri yapılacaktır.
```bash
git clone https://github.com/sqlmapproject/sqlmap.git
```
Doğrulama:
```bash
python sqlmap.py --help
```

#### 3.4 Metasploit Framework Kurulumu
Metasploit, güvenlik açığı doğrulama ve exploit testleri için kullanılacaktır.
```bash
sudo apt install metasploit-framework
msfconsole
```

#### 3.5 Burp Suite Kurulumu ve API Entegrasyonu
Burp Suite, web uygulamalarının güvenlik testleri için kullanılacaktır.
- Kurulum: https://portswigger.net/burp
- Python API entegrasyonu için `requests` kütüphanesi kullanılacaktır:
```bash
pip install requests
```

#### 3.6 Web Tabanlı Yönetim Paneli (Flask)
Yönetim paneli proje içinde tarama ve raporlama modüllerini kontrol etmek için geliştirilecektir.
```bash
pip install flask
```
Basit test:
```python
from flask import Flask
app = Flask(__name__)
@app.route("/")
def home():
    return "Sızma Testi Otomasyon Aracı Yönetim Paneli"
app.run()
```
Erişim: http://localhost:5000

---

### 4. Proje Klasör Yapısı
```
penetration-test-automation/
├── scanner/
│   ├── nmap_scanner.py
│   ├── sqlmap_scanner.py
├── exploits/
│   └── metasploit_module.py
├── webpanel/
│   ├── app.py
│   ├── templates/
├── reports/
└── requirements.txt
```

---

### 5. Ortam Testi ve Doğrulama
- Python çalışıyor mu?
- Nmap taraması başarılı mı?
- SQLMap komutu çalışıyor mu?
- Metasploit açılıyor mu?
- Web paneli erişilebilir mi?

Örnek test:
```bash
nmap localhost
```

---

### 6. Sonuç
Bu dokümanda, Sızma Testi Otomasyon Aracı projesi için gerekli geliştirme ortamının kurulumu ve yapılandırma adımları proje odaklı olarak açıklanmıştır. Kurulan bu ortam sayesinde, projenin zafiyet tarama, analiz ve raporlama modüllerinin geliştirilmesi için gerekli altyapı hazırlanmıştır.

Tüm araçların entegre bir şekilde çalışabilecek biçimde kurulması, projenin ilerleyen aşamalarında otomasyon süreçlerinin sağlıklı bir şekilde geliştirilmesine olanak sağlayacaktır. Bu sayede ekip üyeleri aynı geliştirme ortamını kullanarak uyumlu ve verimli bir şekilde çalışabilecektir.

