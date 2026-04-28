# Hafta 6 — Güvenlik Açığı Giderme ve Raporlama

> **Branch:** `dev/sefa-security-fixes` (önerilen merge hedefi: `dev/sefa`)
> **Sorumlu:** M. Sefa Kozan
> **Modül:** SQLMap Entegrasyon Modülü
> **Görev:** "Güvenlik Açıklarının Giderilmesi ve Raporlanması" (Hafta 6, Yüksek öncelik)

---

## Özet

Bu sprintte SQLMap entegrasyon modülünde **11 güvenlik açığı** tespit edilip giderildi. Açıkların 2'si **Kritik** (SSRF ve Argument Injection), 4'ü **Yüksek**, 4'ü **Orta** ve 1'i **Düşük** seviyededir. Tüm açıklar için regresyon testi yazıldı; toplam test sayısı **115'ten 183'e** çıktı ve hepsi geçiyor.

Detaylı inceleme için ekteki PDF raporu okunmalıdır:
**`Guvenlik_Acigi_Giderme_ve_Raporlama.pdf`** (14 sayfa)

---

## Değişiklik Özeti

| Dosya | Değişiklik |
|---|---|
| `src/utils/validators.py` | +411 satır — 5 yeni doğrulayıcı, SSRF koruması, beyaz liste sanitize |
| `src/config/sqlmap_config.py` | +44 satır — yeni doğrulamaların entegrasyonu, `allow_internal_targets` bayrağı |
| `src/scanners/sqlmap_scanner.py` | +194 satır — komut maskeleme, kaynak limiti, symlink koruması, log iyileştirmeleri |
| `src/parsers/sqlmap_parser.py` | +6 satır — sessiz hata yutmanın kaldırılması |
| `tests/test_security.py` | +481 satır (YENİ) — 68 güvenlik regresyon testi |

**Net etki:** +1.123 satır eklendi, 91 satır silindi.

---

## Tespit Edilen ve Giderilen Açıklar

| # | Zafiyet | CWE | Seviye | Durum |
|---|---|---|:-:|:-:|
| F-01 | SSRF — Dahili IP / Cloud metadata | CWE-918 | Kritik | Kapatıldı |
| F-02 | Argument Injection — SQLMap tehlikeli bayraklar | CWE-88 | Kritik | Kapatıldı |
| F-03 | CRLF Injection — header/cookie/data | CWE-93 | Yüksek | Kapatıldı |
| F-04 | Path Traversal — `output_dir` | CWE-22 | Yüksek | Kapatıldı |
| F-05 | Yetersiz Sanitizasyon — kara liste | CWE-78/20 | Yüksek | Kapatıldı |
| F-06 | Resource Exhaustion — sınırsız async | CWE-770 | Yüksek | Kapatıldı |
| F-07 | Hassas Veri Loglama — komut satırı | CWE-532 | Orta | Kapatıldı |
| F-08 | Sessiz Hata Yutma — `except: pass` | CWE-703 | Orta | Kapatıldı |
| F-09 | Symlink Takip — `_cleanup_temp_dir` | CWE-59 | Orta | Kapatıldı |
| F-10 | Göreceli Yol İstismarı — `_find_sqlmap` | CWE-426 | Orta | Kapatıldı |
| F-11 | Yetersiz URL Kontrolü — CR/LF | CWE-93 | Düşük | Kapatıldı |

---

## Doğrulama

```bash
# Birim testler
$ python3 -m pytest tests/ -v
============================= 183 passed in 0.93s =============================

# SAST analizi (Bandit)
$ bandit -r src/
Total issues (by severity):
    High: 0
    Medium: 0
    Low: 8 (subprocess kullanımı — kabul edilen risk, raporda açıklandı)
```

---

## Geriye Dönük Uyumluluk

Mevcut kullanım (mock kullanan testler, `example.com` domain'i ile yapılan taramalar) etkilenmemiştir. Bütün **115 mevcut test** olduğu gibi geçmektedir.

**Tek davranış değişikliği:** Artık dahili IP'lere (127.0.0.1, 192.168.x.x, vb.) yapılan taramalar varsayılan olarak reddediliyor. Yerel test ortamlarında bu davranışı eski haline getirmek için `SQLMapConfig` oluşturulurken `allow_internal_targets=True` parametresi açıkça verilmelidir:

```python
# YENİ: yerel test için
config = SQLMapConfig(
    target_url="http://127.0.0.1/test?id=1",
    allow_internal_targets=True,
)
```

---

## Sonraki Sprint İçin Öneriler

PDF raporun 6. bölümünde detaylı şekilde açıklanmıştır. Kısaca:

1. **Hafta 7:** Dependency pinning + `pip-audit` CI entegrasyonu (Nehir koordineli)
2. **Hafta 7:** GitHub Actions üzerinde otomatik güvenlik kapısı
3. **Hafta 8:** DNS rebinding koruması
4. **Hafta 9:** Audit log tablosu (Nursena koordineli)
5. **Hafta 10:** API rate limiting

---

## Dosyalar

```
kod_degisiklikleri/
├── HAFTA-6-DEGISIKLIKLER.diff     ← Tüm değişikliklerin git diff'i
├── src/
│   ├── utils/validators.py        ← Güçlendirilmiş doğrulayıcı
│   ├── config/sqlmap_config.py    ← Doğrulama entegrasyonu
│   ├── scanners/sqlmap_scanner.py ← Sertleştirilmiş scanner
│   └── parsers/sqlmap_parser.py   ← Log eklendi
└── tests/
    └── test_security.py           ← 68 yeni test (YENİ DOSYA)
```
