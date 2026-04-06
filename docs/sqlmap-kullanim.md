# SQLMap Entegrasyon Modülü — Kullanım Kılavuzu

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

## 📖 Kullanım Örnekleri

### Hızlı Tarama

```python
from src.scanners.sqlmap_scanner import SQLMapScanner
from src.config.sqlmap_config import SQLMapConfig

scanner = SQLMapScanner()

config = SQLMapConfig.quick_scan(
    url="http://testphp.vulnweb.com/listproducts.php?cat=1",
    dbms="mysql"
)

result = scanner.scan(config)

if result.is_vulnerable:
    print(f"{result.vulnerability_count} zafiyet bulundu!")
    print(result.generate_summary())
```

### Özel Yapılandırma ile Tarama

```python
config = SQLMapConfig(
    target_url="http://hedef.com/login",
    data="username=admin&password=test",
    dbms="postgresql",
    level=3,
    risk=2,
    techniques="BEUST",
    threads=5,
)
result = scanner.scan(config)
```

### Hazır Profiller

| Profil | Level | Risk | Teknikler | Ne Zaman Kullanılır |
|--------|-------|------|-----------|---------------------|
| `quick_scan()` | 1 | 1 | BE | Hızlı keşif |
| `standard_scan()` | 3 | 2 | BEUST | Günlük tarama |
| `deep_scan()` | 5 | 3 | BEUSTQ | Kapsamlı denetim |
| `post_scan()` | 3 | 2 | BEUST | Form/Login testi |

### Sonuçları Raporlama Modülüne Aktarma

```python
# Veritabani tablolarina uyumlu kayitlar
db_records = result.to_db_records()
# db_records["scan"]            → SCANS tablosu
# db_records["vulnerabilities"] → VULNERABILITIES tablosu
# db_records["report"]          → REPORTS tablosu

# Diger formatlar
result.to_json()            # JSON string
result.to_report_dict()     # Raporlama sozlugu
result.generate_summary()   # Turkce metin ozeti
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
