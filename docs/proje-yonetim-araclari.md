<h1 align="center">Sızma Testi Otomasyon Aracı — Proje Yönetim Araçları Rehberi</h1>

> **Proje:** Sızma Testi Aracı (Penetration Testing Tool)

> **Hazırlayan:** Muhammet Sefa KOZAN

> **Amaç:** Ekip üyelerinin Jira, Slack, GitHub ve GitHub Desktop araçlarını etkin kullanabilmesi  

&nbsp;

## 📋 İçindekiler

1. [Neden Bu Araçlara İhtiyacımız Var?](#neden-bu-araçlara-ihtiyacımız-var)
2. [GitHub — Kod Deposu](#1-github--kod-deposu)
3. [GitHub Desktop — Görsel Git İstemcisi](#2-github-desktop--görsel-git-i̇stemcisi)
4. [Jira — Proje Yönetimi](#3-jira--proje-yönetimi)
5. [Slack — Ekip İletişimi](#4-slack--ekip-i̇letişimi)
6. [Araçların Birbirine Entegrasyonu](#araçların-birbirine-entegrasyonu)
7. [Ekip İş Akışı (Workflow)](#ekip-i̇ş-akışı-workflow)
8. [Sık Sorulan Sorular (*)](#sık-sorulan-sorular)

&nbsp;

## Neden Bu Araçlara İhtiyacımız Var?

Projemiz; zafiyet tarama motoru, raporlama modülü, özelleştirilebilir test senaryoları ve web yönetim paneli gibi birden fazla bileşenden oluşuyor. 5 kişilik bir ekip olarak:

- Kodun kaybolmaması için → **GitHub**
- Kodla görsel, kolay çalışmak için → **GitHub Desktop**
- Kimin ne yapacağını takip etmek için → **Jira**
- Anlık iletişim ve bildirimler için → **Slack**

araçlarını kullanacağız. Bu araçlar yalnızca projemize özgü tercihler değil; günümüz yazılım sektöründe profesyonel ekiplerin aktif olarak kullandığı endüstri standardı çözümlerdir.

&nbsp;

## 1. GitHub — Kod Deposu

### GitHub Nedir?

GitHub, kodunuzu bulutta saklayan, ekip üyelerinin aynı kod tabanı üzerinde eş zamanlı çalışmasına olanak tanıyan bir platformdur. Git sürüm kontrol sistemini web arayüzüyle sunar.

### Kurulum ve Hesap Açma

1. [github.com](https://github.com) adresine gidin
2. **"Sign up"** butonuna tıklayın
3. Kullanıcı adı, e-posta ve şifre belirleyin
4. E-posta doğrulamasını tamamlayın

### Proje Deposu (Repository) Yapısı

```
penetration-testing-tool/
├── README.md                      # Projeye genel bakış
├── requirements.txt               # Python 3.10+ bağımlılıkları (TR-01)
├── src/
│   ├── discovery/                 # FR-01: Otomatik varlık keşfi (Nmap entegrasyonu)
│   ├── vulnerability/             # FR-02: CVE taraması, SQLi & XSS tespiti
│   ├── exploitation/              # FR-03: False positive doğrulama senaryoları
│   ├── reporter/                  # FR-04: CVSS skorlamalı PDF/HTML rapor üretimi
│   ├── web-panel/                 # Web tabanlı yönetim paneli
│   └── core/                      # TR-02: Modüler mimari çekirdeği
│       ├── storage.py             # TR-03: AES-256 şifreli veri depolama
│       └── consent.py             # Dijital onay mekanizması
├── tests/                         # Birim ve entegrasyon testleri
└── docs/                          # Dokümantasyon
    ├── gereksinim-analizi.md
    └── proje-yonetim-araclari.md
```

### Temel GitHub Kavramları

| Kavram | Açıklama |
|--------|----------|
| **Repository (Repo)** | Projenin tüm dosyalarının bulunduğu klasör |
| **Branch (Dal)** | Ana koddan bağımsız çalışma alanı |
| **Commit** | Yapılan değişikliklerin kaydedilmesi |
| **Pull Request (PR)** | Değişikliklerin ana koda eklenmesi talebi |
| **Merge** | İki dalı birleştirme |
| **Clone** | Depoyu bilgisayara kopyalama |

### Branch Stratejisi

```
main (ana kod - her zaman çalışır durumda)
├── pm (Project Manager)
│   └──  nehir
├── dev (Developer)
│   ├── sefa
│   ├── sevval
│   ├── muhammed
│   └── nursena
├── scrum-ai (AI)
│   └── dokumanlar
```

**Kural:** Hiçbir zaman doğrudan `main` dalına kod yazmayın!

### Commit Mesajı Yazma Kuralları

```
✅ İyi commit mesajları:
feat: zafiyet tarama motoru için Nmap entegrasyonu eklendi
fix: SQL injection tarama hatasında boş sonuç sorunu düzeltildi
docs: README güncellendi, kurulum adımları eklendi

❌ Kötü commit mesajları:
düzelttim
asdfgh
işte tamam
```

&nbsp;

## 2. GitHub Desktop — Görsel Git İstemcisi

### GitHub Desktop Nedir?

Komut satırı kullanmadan GitHub ile çalışmanızı sağlayan masaüstü uygulamasıdır. Git komutlarını bilmeden de kolayca commit, push, pull işlemleri yapabilirsiniz.

### Kurulum

1. [desktop.github.com](https://desktop.github.com) adresine gidin
2. İşletim sisteminize uygun sürümü indirin (Windows / macOS)
3. Kurulumu tamamlayın
4. GitHub hesabınızla giriş yapın

### Temel İşlemler

#### Depoyu Bilgisayara Kopyalama (Clone)

```
File → Clone Repository → URL sekmesi
→ github.com/[kullaniciadiniz]/penetration-testing-tool
→ Klasörü seçin → Clone
```

#### Yeni Branch Oluşturma

```
Current Branch (üst menü) → New Branch
→ İsim: dev/sefa
→ Create Branch
```

#### Değişiklikleri Kaydetme (Commit)

```
Sol panel: değiştirilen dosyalar görünür
→ Summary kısmına commit mesajı yazın
→ "Commit to dev/sefa" butonuna tıklayın
```

#### Değişiklikleri GitHub'a Gönderme (Push)

```
Commit sonrası: "Push origin" butonu görünür
→ Tıklayın → Değişiklikler GitHub'a yüklendi!
```

#### Pull Request Oluşturma

```
Branch'i push ettikten sonra:
→ "Create Pull Request" butonu belirir
→ Tıklayın → Tarayıcıda GitHub açılır
→ Açıklama ekleyin → Ekip arkadaşınızı Reviewer olarak ekleyin
→ "Create Pull Request"
```

### Güncel Kodunu Çekme (Fetch & Pull)
Bir ekip arkadaşın yeni kod gönderdiğinde, o değişiklikleri kendi bilgisayarına almak için şu adımları izle:
1. GitHub Desktop'ı aç
2. Üst menüden "Fetch origin" butonuna tıkla
   → GitHub'daki yeni değişiklikleri kontrol eder (henüz indirmez)
3. "Pull origin" butonu belirirse tıkla
   → Değişiklikler bilgisayarına indirilir

> ⚠️ Önemli: Kodlamaya başlamadan önce her gün mutlaka Fetch & Pull yapın. Aksi halde ekip arkadaşlarınızın değişikliklerinden habersiz çalışırsınız ve merge conflict riski artar.

### Sık Yapılan Hatalar ve Çözümleri

| Hata | Çözüm |
|------|-------|
| Push yapılamıyor | Önce "Fetch origin" sonra "Pull" yapın |
| Merge conflict | GitHub Desktop çakışan satırları gösterir, manuel düzeltin |
| Yanlış branch'te commit | Branch değiştirip "Cherry-pick*" ile aktarabilirsiniz |

&nbsp;

## 3. Jira — Proje Yönetimi

### Jira Nedir?

Jira, ekip görevlerini takip etmek için kullanılan proje yönetim aracıdır. Kim, ne zaman, neyi yapacak sorularının cevabını görsel bir Kanban/Scrum panosu üzerinde yönetir.

### Kurulum ve Erişim

1. [atlassian.com/software/jira](https://www.atlassian.com/software/jira) adresine gidin
2. **"Get it free"** ile ücretsiz hesap açın
3. Proje sahibi ekip üyelerini davet eder: **Settings → People → Invite**

### Proje Yapılandırması

**Proje Adı:** `penetration-testing-tool`  
**Proje Tipi:** Scrum (sprint bazlı çalışmak için)

#### Sprint Planlaması

Projemizi 4 Sprint'e bölebiliriz:

| Sprint | Süre | Kapsam | İlgili Gereksinim |
|--------|------|--------|-------------------|
| Sprint 1 | 1. Hafta | Python 3.10+ ortam kurulumu, modüler mimari iskeletinin oluşturulması, Nmap & SQLMap & Metasploit RPC bağlantılarının test edilmesi | TR-01, TR-02, TR-04 |
| Sprint 2 | 2. Hafta | Otomatik varlık keşfi (aktif cihaz, açık port, servis tespiti), AES-256 ile güvenli veri depolama | FR-01, TR-03 |
| Sprint 3 | 3. Hafta | CVE taraması ve web zafiyet tespiti (SQLi, XSS), dijital onay mekanizması, false positive doğrulama senaryoları | FR-02, FR-03 |
| Sprint 4 | 4. Hafta | CVSS skorlamalı PDF/HTML rapor üretimi, web yönetim paneli, %90 doğruluk hedefinin lab ortamında test edilmesi | FR-04 |

> 📝 **Not:** Gereksinim analizindeki kodlar:  
TR → Technical Requirement (Teknik Gereksinim) — sistemin altyapısal standartları.  
FR → Functional Requirement (Fonksiyonel Gereksinim) — sistemin kullanıcıya sunması gereken işlevler.  

### Issue Türleri

| Tür | Kullanım |
|-----|----------|
| **Epic** | Büyük özellik grubu (örn: Tarama Motoru) |
| **Story** | Kullanıcı perspektifinden özellik |
| **Task** | Yapılacak teknik iş |
| **Bug** | Hata kaydı |

#### Örnek Issue Oluşturma

```
Başlık  : Nmap ile port tarama modülü entegre edilmeli
Tür     : Task
Atanan  : [İlgili ekip üyesi]
Epic    : Zafiyet Tarama Motoru
Sprint  : Sprint 2
Öncelik : High
Açıklama:
  - Nmap Python kütüphanesi (python-nmap) entegre edilmeli
  - Port tarama sonuçları JSON formatında döndürülmeli
  - OWASP standartlarına uygun tarama parametreleri ayarlanmalı
```

### Kanban Panosu Kolonları

```
To Do   →   In Progress  →   In Review  →   Done
```

- **To Do:** Henüz başlanmamış görevler
- **In Progress:** Üzerinde çalışılan görevler
- **In Review:** Pull Request açılmış, gözden geçirilmeyi bekleyen
- **Done:** Tamamlanmış görevler

### GitHub ile Jira Entegrasyonu

Commit mesajlarına Jira issue numarasını ekleyerek otomatik bağlantı kurabilirsiniz:

```bash
# Örnek:
feat: [PTT-7] Nmap port tarama entegrasyonu tamamlandı
fix: [PTT-3] Boş IP adresi girişinde crash hatası düzeltildi
```

&nbsp;

## 4. Slack — Ekip İletişimi

### Slack Nedir?

Slack, ekip iletişimi için kullanılan anlık mesajlaşma platformudur. E-postanın aksine hızlı, kanallara ayrılmış ve araçlarla entegre çalışır.

### Kurulum

1. [slack.com](https://slack.com) adresine gidin
2. **"Get started for free"** ile workspace oluşturun
3. Workspace adı: `penetration-testing-tool`
4. Diğer ekip üyelerini e-posta ile davet edin

### Kanal (Channel) Yapısı

Projemizin kanalları:

| Kanal | Amaç | İlgili Gereksinim |
|-------|------|-------------------|
| `#genel` | Genel duyurular ve ekip sohbeti | — |
| `#varlik-kesfi` | Nmap ile aktif cihaz ve port tarama geliştirmesi | FR-01 |
| `#zafiyet-tespiti` | CVE, SQLi, XSS tarama modülü tartışmaları | FR-02 |
| `#dogrulama-exploitation` | False positive doğrulama senaryoları | FR-03 |
| `#raporlama` | CVSS skorlamalı PDF/HTML rapor modülü | FR-04 |
| `#web-panel` | Web yönetim paneli geliştirmesi | — |
| `#hatalar-buglar` | Bulunan hata bildirimleri | — |
| `#daily-standup` | Günlük durum güncellemeleri | — |
| `#github-bildirimleri` | Otomatik GitHub bildirimleri | — |

### Günlük Standup Formatı

Her gün `#daily-standup` kanalına şu formatta mesaj atın:

```
📅 [Tarih]
✅ Dün ne yaptım: Nmap entegrasyon kodu tamamlandı
🔄 Bugün ne yapacağım: Unit testler yazılacak
🚧 Sorun: Port 443 tarama izni eksik, araştırıyorum
```

### GitHub Entegrasyonu (Project Manager için)

Slack'e GitHub uygulamasını ekleyerek otomatik bildirim alabilirsiniz:

```
Apps → GitHub → Connect
→ Repository: penetration-testing-tool
→ Subscribe: /github subscribe [repo-linki] reviews comments pushes
```

Bu sayede her commit, PR ve yorum `#github-bildirimleri` kanalına otomatik düşer.

### Faydalı Slack Kısayolları

| Kısayol | İşlev |
|---------|-------|
| `Ctrl + K` | Hızlı kanal/kişi arama |
| `@isim` | Kişiye bildirim gönderme |
| `@channel` | Tüm kanala bildirim |
| `/remind` | Hatırlatıcı kurma |
| `:emoji:` | Emoji ekleme |

&nbsp;

## Araçların Birbirine Entegrasyonu

```
┌─────────────┐     commit/PR bildirimi     ┌─────────────┐
│   GitHub    │ ─────────────────────────→  │    Slack    │
└─────────────┘                             └─────────────┘
       ↑                                           │
    kod push                                 issue güncelleme
       │                                           ↓
┌─────────────────┐                         ┌─────────────┐
│ GitHub Desktop  │                         │     Jira    │
└─────────────────┘                         └─────────────┘
```

&nbsp;

## Ekip İş Akışı (Workflow)

### Yeni Bir Görev Başlarken

```
1. Jira'dan görevi "In Progress"a taşı
2. Kodu yaz, kendi branch'ine commit et
3. Slack'te ekibe haber ver: "#scanner-modulu - Nmap modülüne başladım"
```

### Görevi Tamamlarken

```
1. Tüm değişiklikleri commit et ve push et
2. GitHub'da Pull Request aç
3. Bir ekip arkadaşını reviewer olarak ata
4. Jira'da görevi "In Review"ya taşı
5. Slack'te bildir: "PTT-42 için PR açtım, review bekliyor"
```

&nbsp;

## Sık Sorulan Sorular

**S: Commit'i sildim, geri alabilir miyim?**  
C: Evet. GitHub Desktop → History → Sağ tık → Revert.

**S: Yanlış branch'e commit attım, ne yapabilirim?**  
C: Doğru branch'e geç → History → Yanlış commit'e sağ tık → Cherry-pick. *(Cherry-pick: Başka bir branch'teki belirli bir commit'i alıp mevcut branch'ine uygulamana yarayan işlemdir.)*

**S: Merge conflict nasıl çözülür?**  
C: GitHub Desktop çakışan dosyaları gösterir. VS Code'da açıp `<<<<<<`, `======`, `>>>>>>` işaretleri arasında hangi kodu tutacağınızı seçin, kaydedin ve commit edin.

**S: Jira'ya kaç görev gireceğiz?**  
C: Her ekip üyesi sprint başında en az 3-5 görev tanımlamalı. Küçük ve ölçülebilir görevler tercih edilmeli.

**S: Slack'te ne kadar paylaşım yapmalıyız?**  
C: Günde en az bir standup mesajı. Bir sorunla karşılaştığınızda hemen ilgili kanala yazın, e-posta atmayın.

&nbsp;

## 📌 Önemli Linkler

| Araç | Link |
|------|------|
| GitHub Reposu | https://github.com/Nehirkktn/penetration-testing-tool |
| Jira Panosu | https://sibersavascilar.atlassian.net/jira |
| Slack Workspace | https://siber-savascilar-ptt.slack.com |

&nbsp;

<p align="right">
  <i><b>Muhammet Sefa KOZAN</b> - Yazılım Mühendisi</i>
</p>