# 🛠️ Buluşma İçin Git Komutları

> Bu doküman, buluşmada (Meet veya yüz yüze) her arkadaşın sırayla
> kopyalayıp yapıştıracağı git komutlarını içerir.
>
> **Önce `DAGITIM_PLANI.md`'yi okuyun**, kimin hangi dosyaları
> push'layacağı orada yazılı.

---

## 📦 Buluşmadan Önce Herkes Hazırlasın

### Git kurulumu
- **Windows:** https://git-scm.com/download/win → indir + kur (next, next, next)
- **macOS:** Terminal aç, `git --version` yaz. Yoksa `xcode-select --install`
- **Linux:** `sudo apt install git`

### GitHub hesabı
- https://github.com → hesap aç (yoksa)
- Profilden username'leri grupta paylaşın (Nehir'in repo'ya eklemesi için)

### Git kimlik ayarı (her bilgisayarda bir kez)
```bash
git config --global user.name "Adın Soyadın"
git config --global user.email "github-eposta@adresin.com"
```
> Email **GitHub hesabında kayıtlı email** olmalı, yoksa commit'in
> profilinle eşleşmez.

---

## 🎬 ADIM 1: Nehir Repo Açıyor

> Bu kısmı sadece Nehir yapar.

### 1.1 GitHub'da yeni repo oluştur

1. https://github.com → sağ üst **+** → **New repository**
2. **Repository name:** `sizma-testi-otomasyon-araci` (veya beğendiğin bir ad)
3. **Description:** "Fırat Üniversitesi Yazılım Mühendisliği Temelleri
   Dönem Projesi - Siber Savaşçılar Ekibi"
4. **Public** seç (hocaya gösterebilmek için)
5. **Initialize this repository with: HİÇBİR ŞEY SEÇME** (README, .gitignore,
   license eklemeden boş bırak)
6. **Create repository**

### 1.2 Diğer arkadaşları Collaborator olarak ekle

1. Repo sayfasında → **Settings** → **Collaborators**
2. **Add people** → arkadaşların GitHub username'lerini gir
3. Her birine davet gönder (onlar email'den/GitHub bildiriminden kabul edecek)

### 1.3 Bilgisayarda repo'yu kurmak

**Mira/sen Nehir'le birlikteysen:**

Senin elinde son zip dosyası var (Docker'lı hali). Nehir'in repo'sunu o
dosyalarla doldurun:

```bash
# Senin elindeki zip'in açıldığı klasöre git
cd C:\Users\F0TR\Downloads\siber-savascilar-final_son

# Bu klasörü git repo'su haline getir
git init
git branch -M main

# Nehir'in açtığı repo'yu remote olarak ekle (URL'yi Nehir verir)
git remote add origin https://github.com/<nehir-username>/sizma-testi-otomasyon-araci.git

# ÖNEMLİ: Sadece çatı dosyalarını ilk commit'e koy
# (Modüller diğer arkadaşların branch'lerinde gelecek)

# Önce her şeyi ignore'a al, sonra sadece çatı dosyalarını ekle
# (Bunu manuel yapacağız aşağıda)
```

**Çatı dosyalarını main'e push'lamak için Nehir'in adımları:**

```bash
# Henüz commit yapmadan, sadece bu dosyaları add edelim:
git add README.md
git add requirements.txt
git add setup.py
git add .gitignore
git add LICENSE
git add baslat.sh
git add Dockerfile
git add .dockerignore
git add DAGITIM_PLANI.md
git add KOMUTLAR.md
git add data/.gitkeep
git add reports/.gitkeep

# Boş klasörlerin görünmesi için .gitkeep dosyaları
# (Eğer yoksa oluşturalım — komut sırayla:)
# touch data/.gitkeep  (Windows: type nul > data\.gitkeep)
# touch reports/.gitkeep

# İlk commit
git commit -m "İlk kurulum: proje çatısı ve dokümanlar"

# main'e push
git push -u origin main
```

✅ **Bu noktada repo'da sadece çatı dosyaları var.** Sefa'nın, Nursena'nın,
Muhammed'in, Şevval'in modülleri henüz yok.

---

## 🎬 ADIM 2: Herkes Kendi Branch'ini Açıyor

> Her arkadaş bu adımı **paralel** yapabilir (aynı anda).

### Genel template — herkes adapte ediyor

```bash
# 1. Repo'yu klonla (sadece bir kere)
git clone https://github.com/<nehir-username>/sizma-testi-otomasyon-araci.git
cd sizma-testi-otomasyon-araci

# 2. Kendi branch'ini oluştur
git checkout -b <senin-branch-adın>

# 3. Mira'nın paylaştığı son zip dosyasından SENİN dosyalarını bu klasöre kopyala
#    (DAGITIM_PLANI.md'de hangi dosyaların senin olduğu yazılı)

# 4. Dosyaları staging area'ya ekle
git add <senin-dosyaların>

# 5. Commit
git commit -m "<senin-modülünün-açıklaması>"

# 6. Push
git push -u origin <senin-branch-adın>
```

---

## 👤 Kişi Kişi Komutlar

> **Mira:** Bu komutları arkadaşlarına WhatsApp'tan veya buluşmada
> kopyala-yapıştır olarak gönder.

### 🟢 Sefa Kozan

```bash
# Repo'yu klonla
git clone https://github.com/<nehir-username>/sizma-testi-otomasyon-araci.git
cd sizma-testi-otomasyon-araci

# Branch aç
git checkout -b sefa-sqlmap-test

# (Mira'dan gelen zip'i bir kenara açtın, oradan dosyaları buraya kopyala
# Aşağıdaki dosyalar SENİN sorumluluğunda — bunları kopyalamalısın:)
#
#   siber_savascilar/__init__.py
#   siber_savascilar/__main__.py
#   siber_savascilar/cli.py
#   siber_savascilar/core/__init__.py
#   siber_savascilar/core/models.py
#   siber_savascilar/core/validators.py
#   siber_savascilar/scanners/sqlmap_scanner.py
#   tests/  (tüm klasör)

# Add + Commit + Push
git add siber_savascilar/__init__.py
git add siber_savascilar/__main__.py
git add siber_savascilar/cli.py
git add siber_savascilar/core/__init__.py
git add siber_savascilar/core/models.py
git add siber_savascilar/core/validators.py
git add siber_savascilar/scanners/sqlmap_scanner.py
git add tests/

git commit -m "SQLMap entegrasyonu, veri modelleri, validators ve test paketi (394 test)"

git push -u origin sefa-sqlmap-test
```

---

### 🟢 Nursena Karaduman

```bash
git clone https://github.com/<nehir-username>/sizma-testi-otomasyon-araci.git
cd sizma-testi-otomasyon-araci

git checkout -b nursena-tarayicilar

# Şu dosyaları kopyala (Mira'nın paylaştığı zip'ten):
#   siber_savascilar/core/database.py
#   siber_savascilar/scanners/__init__.py
#   siber_savascilar/scanners/base.py
#   siber_savascilar/scanners/port_scanner.py
#   siber_savascilar/scanners/sqli_scanner.py
#   siber_savascilar/scanners/xss_scanner.py
#   siber_savascilar/scanners/misconfig_scanner.py
#   siber_savascilar/scanners/sensitive_data_scanner.py
#   siber_savascilar/scanners/access_control_scanner.py

git add siber_savascilar/core/database.py
git add siber_savascilar/scanners/__init__.py
git add siber_savascilar/scanners/base.py
git add siber_savascilar/scanners/port_scanner.py
git add siber_savascilar/scanners/sqli_scanner.py
git add siber_savascilar/scanners/xss_scanner.py
git add siber_savascilar/scanners/misconfig_scanner.py
git add siber_savascilar/scanners/sensitive_data_scanner.py
git add siber_savascilar/scanners/access_control_scanner.py

git commit -m "Zafiyet tarama motoru: 6 OWASP tarayıcı modülü + SQLite veritabanı"

git push -u origin nursena-tarayicilar
```

---

### 🟢 Muhammed B. Başbay

```bash
git clone https://github.com/<nehir-username>/sizma-testi-otomasyon-araci.git
cd sizma-testi-otomasyon-araci

git checkout -b muhammed-senaryolar

# Şu dosyaları kopyala:
#   siber_savascilar/scanners/scenario_scanner.py
#   scenarios_data/01-gizli-admin-panel.yaml
#   scenarios_data/02-backup-file-exposure.yaml
#   scenarios_data/03-git-exposure.yaml

git add siber_savascilar/scanners/scenario_scanner.py
git add scenarios_data/

git commit -m "Özelleştirilebilir test senaryoları: YAML motor + 3 örnek şablon"

git push -u origin muhammed-senaryolar
```

---

### 🟢 Şevval Duran

```bash
git clone https://github.com/<nehir-username>/sizma-testi-otomasyon-araci.git
cd sizma-testi-otomasyon-araci

git checkout -b sevval-frontend

# Şu dosyaları kopyala:
#   web/index.html
#   web/style.css
#   web/script.js
#   siber_savascilar/api/__init__.py
#   siber_savascilar/api/server.py
#   docs/KURULUM.md

git add web/
git add siber_savascilar/api/
git add docs/KURULUM.md

git commit -m "Web tabanlı yönetim paneli: Flask backend + modern frontend"

git push -u origin sevval-frontend
```

---

### 🟢 Nehir Kökten (kendi modülleri için)

> Nehir'in çatı dosyalarını main'e push'lamasının dışında, kendi modülleri
> için ayrı branch açması gerekiyor.

```bash
# Aynı klasörden devam (zaten clone'ladıydın)
cd sizma-testi-otomasyon-araci

# main'den ayrı branch
git checkout main
git pull
git checkout -b nehir-raporlama-mimari

# Şu dosyaları kopyala:
#   siber_savascilar/reporting/__init__.py
#   siber_savascilar/reporting/generator.py
#   siber_savascilar/orchestrator.py
#   docs/MIMARI.md
#   docs/GOREV_DURUMU.md

git add siber_savascilar/reporting/
git add siber_savascilar/orchestrator.py
git add docs/MIMARI.md
git add docs/GOREV_DURUMU.md

git commit -m "Raporlama modülü, orkestratör ve mimari dokümantasyonu"

git push -u origin nehir-raporlama-mimari
```

---

## 🎬 ADIM 3: Pull Request'ler Açılır

Her arkadaş push'unu yaptıktan sonra GitHub'da:

1. Repo sayfasına git
2. Yeşil banner çıkar: **"<branch-adın> had recent pushes. Compare & pull request"**
3. **Compare & pull request** butonuna bas
4. Başlık olarak commit mesajını otomatik alır
5. **Create pull request**

---

## 🎬 ADIM 4: Merge Sırası (Nehir Yapar)

Nehir, Pull Request'leri **bu sırayla** merge etmeli (bağımlılık sırası):

```
1. sefa-sqlmap-test         ← Modeller, herkes buna bağımlı
2. nursena-tarayicilar      ← BaseScanner'a bağımlı
3. muhammed-senaryolar      ← BaseScanner'a bağımlı
4. sevval-frontend          ← Tarayıcılara bağımlı
5. nehir-raporlama-mimari   ← Tüm modüllere bağımlı
```

Her PR için Nehir:
1. PR sayfasında **Files changed** sekmesinde dosyaları gözden geçirir
2. **Merge pull request** → **Confirm merge**
3. Branch silinmez (geçmiş için kalsın)

---

## 🎬 ADIM 5: Final Doğrulama

Tüm merge'ler bittikten sonra, herkes ya da bir kişi:

### 🐳 Yol A: Docker ile (en kolay)

```bash
# main'i çek
git checkout main
git pull

# Tek komut
docker compose up
```

Tarayıcıdan `http://localhost:5000`

### 🐍 Yol B: Manuel

```bash
# main'i çek
git checkout main
git pull

# Bağımlılıkları kur
pip install -r requirements.txt

# Test paketi çalıştır
python -m pytest tests/

# Beklenen: 394 passed

# Web sunucusunu başlat
python -m siber_savascilar.api.server
# Tarayıcıdan http://localhost:5000
```

✅ Eğer 394 test geçiyor ve web paneli açılıyorsa, **proje birleştirilmiş
ve tamamen çalışır halde**.

---

## 🚨 Olası Sorunlar ve Çözümleri

### "Permission denied (publickey)"
GitHub HTTPS yerine SSH istiyor. HTTPS URL kullan:
```
https://github.com/<username>/repo.git
```
yerine
```
git@github.com:<username>/repo.git
```
**olmasın.** HTTPS'i seçin.

### "Updates were rejected"
Birisi senden önce push'lamış. Önce çek, sonra push:
```bash
git pull origin main --rebase
git push
```

### "Merge conflict"
İki kişi aynı dosyayı değiştirmiş. Mira'ya sor:
> "Claude, <dosya-adı>'nda merge conflict çıktı, çözer misin?"

Bana kopyalayıp yapıştır, çözeyim.

### "fatal: not a git repository"
Yanlış klasördesin. `cd` ile repo klasörüne gir.

### "Author email yok" / "kimlik tanımsız"
```bash
git config --global user.name "Adın Soyadın"
git config --global user.email "github-email@adres.com"
```

---

## 📌 Sefa 1 Haziran'dan Sonra

Sefa Malatya'dan dönünce şu sırayla yapabilirsiniz:
1. Tüm ekip bir Meet kurar
2. `main` branch'i `git pull` ile günceller herkes
3. Sefa kendi test paketi ve modellere son rötuşları yapar
4. Yeni bir PR açıp merge eder
5. Hocaya teslimden önce final demo yaparsınız

---

## 📞 Yardım

Buluşmada takılırsanız Mira'nın yanındaki Claude'a sorabilir:
> "Claude, <şu hatayı> aldık, ne yapalım?"

Hatanın ekran görüntüsünü gönderirseniz daha hızlı çözeriz.
