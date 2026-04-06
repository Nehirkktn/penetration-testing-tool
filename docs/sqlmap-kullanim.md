# SQLMap Entegrasyon Modülü — Kullanım Kılavuzu

> **Siber Savaşçılar** | Fırat Üniversitesi – Yazılım Mühendisliği Temelleri Projesi  
> **Hazırlayan:** Muhammet Sefa Kozan | **Hafta:** 4 | **Son Teslim:** 9 Nisan 2026

## Bu Proje Ne İşe Yarıyor?

Bu modül, **SQL Injection** zafiyetlerini otomatik olarak tespit eder. Arka planda [SQLMap](https://sqlmap.org/) aracını Python üzerinden çalıştırır, çıktısını okur ve yapılandırılmış sonuçlar üretir.

> **❗ Önemli:** Yalnızca **yasal izinli** sistemler üzerinde kullanılmalıdır, aksi halde yasal suçtur (TCK Madde 243-244).

---

## 🔄 Nasıl Çalışıyor?

```
 Kullanıcı          SQLMapConfig        Validators        SQLMapScanner
 (URL girer)   →   (Ayarları topla)  →   (Doğrula)     →   (Çalıştır)
                                                               │
                                                               ▼
                                                           subprocess
                                                         (sqlmap komutu)
                                                               │
                                                               ▼
  Rapor /          ScanResult        SQLMapParser       SQLMap Çıktısı
  Veritabanı  ←  (Sonuç nesnesi)   ←  (Parse et)      ←   (Ham metin)
```

---

## 🚀 Kurulum

```bash
# 1) Bagimliliklari kur
pip3 install -r requirements.txt

# 2) SQLMap kur
brew install sqlmap          # macOS
sudo apt install sqlmap      # Linux
pip3 install sqlmap          # pip ile

# 3) Testleri calistir
python3 -m pytest tests/ -v
```

---

## 📟 Terminal Üzerinden Hızlı Test (Kod Yazmadan Çalıştırma)

> **Kimler için?** Projeyi ilk kez kuran, testleri çalıştırmak isteyen veya hızlıca bir tarama denemek isteyen **tüm ekip üyeleri** bu bölümü kullanabilir.

### Terminal (Konsol) Nedir ve Nereden Açılır?

Bulunduğunuz ortama göre terminali açma yöntemleri ve dosya yolu mantığı farklıdır:

**Yöntem 1: VS Code (IDE) İçinden Açmak (Önerilen)**
- Üst menüden `Terminal → New Terminal` seçin veya `` Ctrl+` `` (Mac için `` Cmd+` ``) kısayolunu kullanın. Ekranın altında terminal açılacaktır.
- IDE içinden açtığınızda **otomatik olarak projenizin bulunduğu klasörde (dizinde)** başlarsınız. Ekstra bir ayar yapmanıza gerek yoktur, doğrudan komutları yazabilirsiniz.

**Yöntem 2: İşletim Sisteminden Harici Olarak Açmak**
- **macOS:** Spotlight'a (Cmd+Space) `Terminal` yazıp açın.
- **Windows:** Başlat menüsüne `cmd` veya `PowerShell` yazıp açın.
- Dışarıdan terminal açtığınızda bilgisayarınızın ana klasöründe başlarsınız. Projeyi çalıştırabilmek için **önce projenin klasörüne gitmeniz gerekir**:

```bash
# Sadece harici terminal actiysaniz proje klasorune gidin:
cd ~/.../penetration-testing-tool
```

### Testleri Çalıştırma

Testler, kodun düzgün çalıştığını doğrular. Herhangi bir değişiklik yaptıktan sonra testleri çalıştırarak bozulan bir şey olup olmadığını kontrol edebilirsiniz.

```bash
# Tum testleri detayli ciktiyla calistir
# -v (verbose) her testin adini ve sonucunu gosterir
python3 -m pytest tests/ -v

# Coverage (kod kapsama) raporu ile calistir
# Hangi satirlarin test edilip edilmedigini gosterir
python3 -m pytest tests/ --cov=src --cov-report=term-missing

# Sadece tek bir modul testini calistir
python3 -m pytest tests/test_sqlmap_config.py -v
python3 -m pytest tests/test_validators.py -v
```

Çıktıda `115 passed` yazıyorsa her şey düzgün çalışıyor demektir ✅

### Python İnteraktif Konsolundan Tarama Başlatma

**Python interaktif konsolu** nedir? Terminal'e `python3` yazıp Enter'a bastığınızda açılan, Python komutlarını satır satır yazıp anında sonuç görebildiğiniz ortamdır. Başında `>>>` işareti görürsünüz.

```bash
# Harici bir terminal actiysaniz once proje klasorune girmelisiniz.
# Eger klasore girmezseniz 'No module named src' hatasi alirsiniz.
cd ~/.../penetration-testing-tool

# Terminalde asagidaki komutu yazip enter'a basin:
python3
```

Şimdi `>>>` işaretini göreceksiniz. Aşağıdaki kodun **tümünü kopyalayıp konsola yapıştırabilirsiniz** (veya sırayla yazıp çalışması beklenen sonuçları görebilirsiniz):

```python
from src.scanners.sqlmap_scanner import SQLMapScanner
from src.config.sqlmap_config import SQLMapConfig

scanner = SQLMapScanner()
# Sonucun 'True' donmesi sqlmap'in sorunsuz bulundugunu gosterir
scanner.check_sqlmap_installed()  

config = SQLMapConfig.quick_scan("http://testphp.vulnweb.com/listproducts.php?cat=1")
result = scanner.scan(config)

print(result.status)  # Cikti: completed
print(result.vulnerability_count)  # Cikti: 4
print(result.generate_summary())
```

Konsoldan çıkmak için `exit()` yazın veya `Ctrl+D` tuşlayın.

### Tek Satırda Yapılandırmayı Kontrol Etme

Interaktif konsola girmeden, terminalden direkt bir Python komutu çalıştırabilirsiniz:

```bash
# Harici bir terminal actiysaniz once proje klasorune girmelisiniz.
python3 -c "
from src.config.sqlmap_config import SQLMapConfig
config = SQLMapConfig.quick_scan('http://testphp.vulnweb.com/listproducts.php?cat=1', dbms='mysql')
print(config.to_command_string())
"
# Cikti: sqlmap -u 'http://testphp.vulnweb.com/...' --dbms 'mysql' --batch --level '1' ...
```

---

## 💻 Python Kodunda Modül Olarak Kullanım (Geliştiriciler İçin)

> **Kimler için?** Modülü kendi Python kodunda kullanmak isteyen **geliştiriciler** — örneğin web arayüzü (UI) entegrasyonu yapan Muhammed veya veritabanı katmanını bağlayan Nursena.

Aşağıdaki örnekler bir `.py` dosyası içine yazılıp çalıştırılır veya Python interaktif konsolunda kullanılır.

### Hızlı Tarama

En basit kullanım — bir URL verin, sonucu alın:

```python
from src.scanners.sqlmap_scanner import SQLMapScanner
from src.config.sqlmap_config import SQLMapConfig

# Scanner nesnesi olustur (SQLMap'i otomatik bulur)
scanner = SQLMapScanner()

# quick_scan: Level 1, Risk 1 ile hizli tarama
config = SQLMapConfig.quick_scan(
    url="http://testphp.vulnweb.com/listproducts.php?cat=1",
    dbms="mysql"
)

# Taramayi baslat ve sonucu al
result = scanner.scan(config)

# Sonuclari ekrana yazdir
if result.is_vulnerable:
    print(f"{result.vulnerability_count} zafiyet bulundu!")
    print(result.generate_summary())
else:
    print("Zafiyet bulunamadi.")
```

### Gelişmiş Tarama (Özel Parametrelerle)

Daha detaylı test için tüm parametreleri kendiniz ayarlayabilirsiniz:

```python
config = SQLMapConfig(
    target_url="http://hedef.com/login",       # Hedef sayfa
    data="username=admin&password=test",        # POST form verisi
    dbms="postgresql",                          # Veritabani turu
    level=3,                                    # Test derinligi (1-5)
    risk=2,                                     # Risk seviyesi (1-3)
    techniques="BEUST",                         # Kullanilacak teknikler
    threads=5,                                  # Ayni anda kac istek gonderilsin
)
result = scanner.scan(config)
```

### Hazır Profiller

Her seferinde parametreleri tek tek yazmak yerine, hazır profiller kullanabilirsiniz:

| Profil | Level | Risk | Teknikler | Ne Zaman Kullanılır |
|--------|-------|------|-----------|---------------------|
| `quick_scan()` | 1 | 1 | BE | İlk deneme, hızlı keşif |
| `standard_scan()` | 3 | 2 | BEUST | Normal günlük tarama |
| `deep_scan()` | 5 | 3 | BEUSTQ | Tam kapsamlı denetim |
| `post_scan()` | 3 | 2 | BEUST | Login formu testi |

### Sonuçları Raporlama Modülüne Aktarma

Tarama sonuçları, Nursena'nın veritabanı tablolarına doğrudan aktarılabilir:

```python
# Veritabani tablolarina uyumlu kayitlar uret
db_records = result.to_db_records()
# db_records["scan"]            → SCANS tablosuna yazilacak veri
# db_records["vulnerabilities"] → VULNERABILITIES tablosuna yazilacak veri
# db_records["report"]          → REPORTS tablosuna yazilacak veri

# JSON formatinda rapor (dosyaya kaydetmek veya API dondurmek icin)
json_rapor = result.to_json()

# Raporlama modulune aktarilacak sozluk
rapor_sozlugu = result.to_report_dict()

# Ekrana Turkce ozet yazdirma
print(result.generate_summary())
```

---

## ⚙️ Yapılandırma Parametreleri

| Parametre | Tip | Varsayılan | Açıklama |
|-----------|-----|------------|----------|
| `target_url` | str | (zorunlu) | Hedef URL |
| `data` | str | "" | POST verisi |
| `dbms` | str | "" | Veritabanı türü (boş = otomatik tespit) |
| `level` | int | 1 | Test derinliği (1-5) |
| `risk` | int | 1 | Risk seviyesi (1-3) |
| `techniques` | str | "" | Injection teknikleri (BEUSTQ) |
| `cookie` | str | "" | Cookie değeri |
| `threads` | int | 1 | Eş zamanlı istek (1-10) |
| `tamper` | list | [] | WAF bypass scriptleri |
| `proxy` | str | "" | Proxy adresi |
| `tor` | bool | False | Tor ağı desteği |

---

## 🗄️ Desteklenen Veritabanları (28+)

| Kategori | DBMS |
|----------|------|
| **Popüler** | MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| **Kurumsal** | IBM DB2, SAP MaxDB, Sybase, Vertica |
| **Diğer** | Firebird, HSQLDB, H2, MonetDB, Apache Derby, CrateDB, CUBRID |

**Kısaltma desteği:** `postgres` → PostgreSQL, `mssql` → Microsoft SQL Server, `mariadb` → MySQL

---

## 🎯 Test Edebileceğiniz Yasal Siteler

| Site | URL | Açıklama |
|------|-----|----------|
| Acunetix | `http://testphp.vulnweb.com/listproducts.php?cat=1` | Her zaman açık test sitesi |
| DVWA | `docker run -d -p 8080:80 vulnerables/web-dvwa` | Lokal kurulum |

---

## ✅ Görev Gereksinimleri

| Gereksinim | Durum |
|---|---|
| SQLMap'i komut satırından çalıştırma | ✅ `subprocess.run()` ile |
| Sonuçları raporlama modülüne aktarma | ✅ `to_db_records()` ile |
| Farklı veritabanı sistemlerini destekleme | ✅ 28+ DBMS |
| Temel parametreleri yapılandırılabilir hale getirme | ✅ URL, DBMS, level, risk, teknikler |
