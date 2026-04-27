# 🐛 SİBER SAVAŞÇILAR — Bug Raporu ve Geliştirici Geri Bildirimi

> **Hazırlayan:** Nursena Karaduman  
> **Tarih:** 27 Nisan 2026  
> **Kapsam:** Tüm branch'lerin kod incelemesi (`dev-nursena`, `dev-sefa`, `dev-muhammed`, `dev-sevval`, `pm-nehir`)  
> **Yöntem:** Statik kod analizi ve yapısal inceleme  

---

## 📊 Özet

| Öncelik | Adet |
|:---|:---|
| 🔴 Kritik | 3 |
| 🟠 Yüksek | 4 |
| 🟡 Orta | 5 |
| 🔵 Düşük | 3 |
| **Toplam** | **15** |

---

## 🔴 KRİTİK BUGLAR

---

### BUG-001 — Hard-Coded Windows Nmap Yolu
- **Dosya:** `dev-nursena` → `scanner_engine/port_scanner.py`
- **Satır:** 9, 12
- **Öncelik:** 🔴 Kritik
- **Tür:** Taşınabilirlik Hatası

**Sorun:**
```python
# MEVCUT — YANLIŞ
os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"
tarayici = nmap.PortScanner(nmap_search_path=(r'C:\Program Files (x86)\Nmap\nmap.exe',))
```
Nmap kurulum yolu Windows'a özgü olarak sabit kodlanmıştır. Proje Linux (Kali Linux) ortamında çalıştırıldığında bu satır `FileNotFoundError` hatası verecek ve port tarama tamamen çalışmayacaktır.

**Çözüm Önerisi:**
```python
import shutil
import sys

def nmap_yolu_bul():
    # Önce sistemde arama yap
    yol = shutil.which("nmap")
    if yol:
        return yol
    # Windows fallback
    if sys.platform == "win32":
        return r"C:\Program Files (x86)\Nmap\nmap.exe"
    raise FileNotFoundError("Nmap sistemde bulunamadı. Lütfen kurun: sudo apt install nmap")

tarayici = nmap.PortScanner(nmap_search_path=(nmap_yolu_bul(),))
```

---

### BUG-002 — URL Çifte Prefix Hatası
- **Dosya:** `dev-nursena` → `scanner_engine/main.py`
- **Satır:** 21, 24
- **Öncelik:** 🔴 Kritik
- **Tür:** Mantık Hatası

**Sorun:**
```python
# main.py içinde hedef_url = "scanme.nmap.org" olarak geliyor
sqli_sonuclar = sqli_test(f"http://{hedef_url}")   # → "http://scanme.nmap.org" ✓
```
Ancak `vuln_scanner.py` içindeki fonksiyonlar da URL'yi doğrudan kullandığı için, eğer kullanıcı `hedef_url` olarak zaten `http://scanme.nmap.org` girerse sonuç `http://http://scanme.nmap.org` olur ve tüm istekler başarısız döner.

**Çözüm Önerisi:**
```python
# main.py içinde URL'yi normalize et
def url_duzenle(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return f"http://{url}"
    return url

hedef_url_tam = url_duzenle(hedef_url)
sqli_sonuclar = sqli_test(hedef_url_tam)
xss_sonuclar = xss_test(hedef_url_tam)
```

---

### BUG-003 — Türkçe Karakter İçeren Veritabanı Dosya Adı
- **Dosya:** `dev-nursena` → `scanner_engine/database.py`
- **Satır:** 7
- **Öncelik:** 🔴 Kritik
- **Tür:** Encoding / Taşınabilirlik Hatası

**Sorun:**
```python
# MEVCUT — YANLIŞ
baglanti = sqlite3.connect("siber_savascılar.db")  # "ı" Türkçe karakter!
```
`ı` harfi ASCII dışı bir karakterdir. Windows sistemlerde `cp1252`, bazı Linux sistemlerinde ise farklı encoding kullanıldığından dosya yolu çözümlenememekte, veritabanı bağlantısı başarısız olmaktadır.

**Çözüm Önerisi:**
```python
# DÜZELTME
baglanti = sqlite3.connect("siber_savascılar.db")
# → şu şekilde değiştir:
baglanti = sqlite3.connect("siber_savascılar.db".encode("utf-8").decode("utf-8"))
# veya daha temiz çözüm:
baglanti = sqlite3.connect("siber_savascılar_db.db")
```

---

## 🟠 YÜKSEK ÖNCELİKLİ BUGLAR

---

### BUG-004 — Bare Exception Kullanımı
- **Dosya:** `dev-nursena` → `scanner_engine/vuln_scanner.py`
- **Satır:** 28, 45
- **Öncelik:** 🟠 Yüksek
- **Tür:** Hata Yönetimi

**Sorun:**
```python
# MEVCUT — YANLIŞ
except:
    print(f"  [!] Bağlantı hatası: {hedef}")
```
`except:` (bare except) tüm hataları — `KeyboardInterrupt`, `SystemExit` dahil — yakalar. Bu durum kullanıcının Ctrl+C ile programı durduramamasına ve gerçek hatanın ne olduğunun anlaşılamamasına neden olur.

**Çözüm Önerisi:**
```python
# DÜZELTME
except requests.exceptions.ConnectionError:
    print(f"  [!] Sunucuya bağlanılamadı: {hedef}")
except requests.exceptions.Timeout:
    print(f"  [!] Zaman aşımı: {hedef}")
except requests.exceptions.RequestException as e:
    print(f"  [!] İstek hatası: {hedef} → {e}")
```

---

### BUG-005 — Veritabanı Şeması ile Kod Uyumsuzluğu
- **Dosya:** `dev-nursena` → `scanner_engine/database.py` ve `docs/veritabani-semasi.md`
- **Öncelik:** 🟠 Yüksek
- **Tür:** Mimari Tutarsızlık

**Sorun:**
`veritabani-semasi.md` belgesinde 5 tablo tasarlanmıştır:
`USERS`, `SCAN_CONFIGS`, `SCANS`, `VULNERABILITIES`, `REPORTS`

Ancak `database.py` içinde yalnızca 2 tablo implement edilmiştir:
`taramalar`, `zafiyetler`

Kullanıcı yönetimi (`USERS`), tarama yapılandırmaları (`SCAN_CONFIGS`) ve raporlama (`REPORTS`) tabloları eksiktir. Bu durum sistemin tasarım belgesiyle çelişmektedir.

**Çözüm Önerisi:**
`database.py` içine eksik tabloları ekle:
```python
cursor.execute("""
    CREATE TABLE IF NOT EXISTS kullanicilar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kullanici_adi TEXT NOT NULL,
        email TEXT NOT NULL,
        sifre_hash TEXT NOT NULL,
        rol TEXT DEFAULT 'user'
    )
""")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS raporlar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tarama_id INTEGER,
        ozet TEXT,
        olusturulma_zamani TEXT,
        FOREIGN KEY (tarama_id) REFERENCES taramalar(id)
    )
""")
```

---

### BUG-006 — SQLMap Scanner ile Merkezi Veritabanı Entegrasyonu Eksik
- **Dosya:** `dev-sefa` → `src/scanners/sqlmap_scanner.py`
- **Öncelik:** 🟠 Yüksek
- **Tür:** Entegrasyon Eksikliği

**Sorun:**
Sefa'nın geliştirdiği `SQLMapScanner` sınıfı kendi içinde bağımsız çalışmaktadır. `ScanResult` nesnesi üretmekte ancak bu sonuçlar Nursena'nın `database.py`'deki `zafiyetler` tablosuna yazılmamaktadır. İki modül birbirinden tamamen habersizdir.

**Çözüm Önerisi:**
`sqlmap_scanner.py` içindeki tarama bittikten sonra şu entegrasyon eklenmeli:
```python
# sqlmap_scanner.py sonuna eklenecek
from database import veritabani_baglant

def sonucu_kaydet(tarama_id, scan_result):
    baglanti = veritabani_baglant()
    cursor = baglanti.cursor()
    for vuln in scan_result.vulnerabilities:
        cursor.execute("""
            INSERT INTO zafiyetler (tarama_id, zafiyet_turu, detay)
            VALUES (?, ?, ?)
        """, (tarama_id, "SQL Injection", vuln.description))
    baglanti.commit()
    baglanti.close()
```

---

### BUG-007 — YAML Senaryo Motoru Ana Sisteme Bağlı Değil
- **Dosya:** `dev-muhammed` → `motor/ozel_tarama_motoru.py`
- **Öncelik:** 🟠 Yüksek
- **Tür:** Entegrasyon Eksikliği

**Sorun:**
Muhammed'in geliştirdiği YAML tabanlı özelleştirilebilir senaryo motoru (`ozel_tarama_motoru.py`) bağımsız çalışmaktadır. `main.py` orkestratörü bu modülü hiç çağırmamaktadır. Senaryolardan dönen bulgular da veritabanına kaydedilmemektedir.

**Çözüm Önerisi:**
`main.py` içine şu çağrı eklenmeli:
```python
from motor.senaryo_okuyucu import senaryo_oku
from motor.ozel_tarama_motoru import ozel_senaryo_calistir

# Senaryolar klasöründeki tüm yaml dosyalarını çalıştır
import glob
for yaml_dosya in glob.glob("senaryolar/*.yaml"):
    senaryo = senaryo_oku(yaml_dosya)
    senaryo_sonuclari = ozel_senaryo_calistir(senaryo, hedef_url)
    tum_sonuclar.extend(senaryo_sonuclari)
```

---

## 🟡 ORTA ÖNCELİKLİ BUGLAR

---

### BUG-008 — Input Validation Modülü Kullanılmıyor
- **Dosya:** `dev-sefa` → `src/utils/validators.py`
- **Öncelik:** 🟡 Orta
- **Tür:** Güvenlik Açığı

**Sorun:**
Sefa'nın yazdığı `validators.py` URL ve IP doğrulama fonksiyonları içermektedir ancak hiçbir tarama modülü bu modülü import etmemektedir. Kullanıcıdan alınan hedef URL doğrudan Nmap ve HTTP isteklerine iletilmektedir.

**Çözüm Önerisi:**
`main.py` başına şunu ekle:
```python
from src.utils.validators import URLValidator

validator = URLValidator()
if not validator.is_valid(hedef_url):
    print("[!] Geçersiz URL formatı. Lütfen geçerli bir URL girin.")
    return
```

---

### BUG-009 — port_scanner.py Sadece 4 Port Tarıyor
- **Dosya:** `dev-nursena` → `scanner_engine/port_scanner.py`
- **Satır:** 14
- **Öncelik:** 🟡 Orta
- **Tür:** Kapsam Eksikliği

**Sorun:**
```python
tarayici.scan(hedef, '80,443,8080,3306', '-T4')
```
Yalnızca 4 port taranmaktadır. Gerçek sızma testlerinde FTP (21), SSH (22), Telnet (23), SMTP (25), DNS (53), RDP (3389) gibi kritik portlar da kontrol edilmelidir.

**Çözüm Önerisi:**
```python
# Yaygın portları kapsayan genişletilmiş tarama
TARANACAK_PORTLAR = '21,22,23,25,53,80,443,445,3306,3389,8080,8443'
tarayici.scan(hedef, TARANACAK_PORTLAR, '-T4')
```

---

### BUG-010 — Frontend Prototype Backend'e Bağlı Değil
- **Dosya:** `dev-sevval` → `script.js`
- **Satır:** 6-9
- **Öncelik:** 🟡 Orta
- **Tür:** Entegrasyon Eksikliği

**Sorun:**
```javascript
function startScan() {
    let status = document.getElementById("status");
    status.innerText = "⏳ Tarama başlatıldı...";
    setTimeout(() => {
        status.innerText = "✅ Tarama tamamlandı!";  // Sahte sonuç!
    }, 3000);
}
```
Tarama başlatma butonu gerçek bir API çağrısı yapmamaktadır. 3 saniye sonra otomatik "tamamlandı" mesajı göstermek yalnızca görsel simülasyondur.

**Çözüm Önerisi:**
```javascript
async function startScan() {
    const hedef = document.querySelector('input').value;
    const status = document.getElementById("status");
    status.innerText = "⏳ Tarama başlatıldı...";
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: hedef})
        });
        const data = await response.json();
        status.innerText = `✅ Tamamlandı! ${data.zafiyet_sayisi} açık bulundu.`;
    } catch (e) {
        status.innerText = "❌ Bağlantı hatası.";
    }
}
```

---

### BUG-011 — requirements.txt Eksik veya Yetersiz
- **Dosya:** `dev-muhammed` → `requirements.txt`
- **Öncelik:** 🟡 Orta
- **Tür:** Bağımlılık Yönetimi

**Sorun:**
`dev-muhammed` branchindeki `requirements.txt` yalnızca 2 kütüphane içermektedir. Projenin çalışması için gereken `python-nmap`, `pyyaml`, `requests`, `sqlalchemy` gibi bağımlılıklar eksiktir. Farklı bilgisayarda kurulum yapıldığında `ModuleNotFoundError` hatası alınacaktır.

**Çözüm Önerisi:**
Ana repodaki `requirements.txt` şu şekilde güncellenmeli:
```
requests==2.31.0
python-nmap==0.7.1
pyyaml==6.0.1
sqlalchemy==2.0.0
flask==3.0.0
beautifulsoup4==4.12.0
```

---

### BUG-012 — Veritabanı Bağlantısı Her Fonksiyonda Ayrı Açılıyor
- **Dosya:** `dev-nursena` → `scanner_engine/database.py`
- **Öncelik:** 🟡 Orta
- **Tür:** Performans / Kaynak Yönetimi

**Sorun:**
`veritabani_baglant()` fonksiyonu her çağrıldığında yeni bir bağlantı açmaktadır. `tablolari_olustur()` içinde de ayrı bir bağlantı açılmakta, yani tek bir tarama başlangıcında 2 ayrı bağlantı oluşturulmaktadır. Bu gereksiz kaynak tüketimine yol açar.

**Çözüm Önerisi:**
```python
# Context manager ile bağlantı yönetimi
from contextlib import contextmanager

@contextmanager
def veritabani_baglant():
    baglanti = sqlite3.connect("siber_savascılar_db.db")
    try:
        yield baglanti
    finally:
        baglanti.close()

# Kullanımı:
with veritabani_baglant() as baglanti:
    cursor = baglanti.cursor()
    # işlemler...
```

---

## 🔵 DÜŞÜK ÖNCELİKLİ BUGLAR

---

### BUG-013 — print() ile Loglama
- **Dosya:** `dev-nursena` → tüm scanner_engine dosyaları
- **Öncelik:** 🔵 Düşük
- **Tür:** Kod Kalitesi

**Sorun:**
Tüm çıktılar `print()` fonksiyonu ile verilmektedir. Gerçek uygulamalarda `logging` modülü kullanılmalıdır. `print()` ile üretilen çıktılar log dosyasına yazılamaz, seviye (DEBUG/INFO/WARNING/ERROR) atanamaz.

**Çözüm Önerisi:**
```python
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# print() yerine:
logger.info("Port taraması başlıyor...")
logger.warning("SQLi açığı bulundu: %s", payload)
logger.error("Bağlantı hatası: %s", e)
```

---

### BUG-014 — Test Hedefi Sabit Kodlanmış
- **Dosya:** `dev-nursena` → `scanner_engine/main.py`, `dev-muhammed` → `test_et.py`
- **Öncelik:** 🔵 Düşük
- **Tür:** Kullanılabilirlik

**Sorun:**
```python
tarama_baslat("scanme.nmap.org")   # main.py
hedef_site = "http://example.com"  # test_et.py
```
Test hedefi sabit kodlanmıştır. Kullanıcıdan komut satırı argümanı alınmamaktadır.

**Çözüm Önerisi:**
```python
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanım: python main.py <hedef_url>")
        print("Örnek   : python main.py scanme.nmap.org")
        sys.exit(1)
    tarama_baslat(sys.argv[1])
```

---

### BUG-015 — Eksik Docstring / Yorum Tutarsızlığı
- **Dosya:** `dev-muhammed` → `motor/ozel_tarama_motoru.py`
- **Öncelik:** 🔵 Düşük
- **Tür:** Dokümantasyon

**Sorun:**
`ozel_senaryo_calistir()` fonksiyonunda `Döndürür:` bölümü eksiktir. Fonksiyonun ne döndürdüğü belgelenmemiştir. Diğer dosyalardaki docstring standardı ile tutarsızlık oluşmaktadır.

**Çözüm Önerisi:**
```python
def ozel_senaryo_calistir(senaryo_verisi, hedef_url):
    """
    Okunan senaryodaki kuralları hedef URL üzerinde test eder.

    Parametreler:
        senaryo_verisi (dict): senaryo_okuyucu.py'den dönen YAML verisi
        hedef_url (str): Test edilecek web adresi

    Döndürür:
        bulgular (list): Her biri 'url', 'bulgu', 'detay' anahtarları içeren dict listesi
    """
```

---

## 📋 Geliştirici Geri Bildirimleri

### → Nursena Karaduman (dev-nursena)
- BUG-001, BUG-002, BUG-003 kritik öncelikte düzeltilmeli. Port scanner'ın Linux'ta da çalışması için `shutil.which()` kullanımı öneriliyor.
- `database.py` tasarım belgesiyle senkronize edilmeli, eksik 3 tablo eklenmeli.
- `except:` ifadeleri spesifik exception türleriyle değiştirilmeli.

### → M. Sefa Kozan (dev-sefa)
- `validators.py` modülü projenin hiçbir yerinde kullanılmıyor. Bu modülün `main.py`'e entegre edilmesi güvenliği artıracak.
- `SQLMapScanner` çıktılarının merkezi `database.py`'e bağlanması gerekiyor.

### → Muhammed Baki Başbay (dev-muhammed)
- YAML senaryo motoru orkestratöre (`main.py`) bağlanmadığı için şu an işlevsiz kalıyor. Entegrasyon için `glob` ile otomatik yaml okuma öneriliyor.
- `requirements.txt` güncellenmeli.

### → Şevval Duran (dev-sevval)
- Frontend prototype harika bir başlangıç! Ancak gerçek API entegrasyonu eklenmeden sistem test edilemez.
- `fetch()` ile backend'e bağlantı kurulması bir sonraki adım olmalı.

### → Nehir Kökten (pm-nehir)
- Mimari tasarım ve gereksinim belgeleri çok başarılı. Modüllerin birbirine bağlanması için bir entegrasyon sprint'i planlanması öneriliyor.

---

*Bu rapor, Hafta 6 "Proje Toparlama ve Test Senaryoları Geliştirme" görevi kapsamında Nursena Karaduman tarafından hazırlanmıştır.*
