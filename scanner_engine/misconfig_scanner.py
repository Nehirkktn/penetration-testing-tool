import requests

def security_misconfiguration_test(url):
    """
    OWASP A05: Security Misconfiguration (Hatalı Güvenlik Yapılandırması) testini gerçekleştirir.

    Açık dizin listeleme, hassas dosya ifşası, hata mesajı sızıntısı,
    varsayılan sayfa varlığı ve güvensiz HTTP başlıklarını test eder.

    Parametreler:
        url (str): Test edilecek web adresi (örn: http://example.com)

    Döndürür:
        sonuclar (list): Bulunan açıkların listesi
    """

    sonuclar = []

    print("\n[*] Security Misconfiguration testi başlıyor...")

    # --- TEST 1: Açık dizin listeleme ---
    print("\n  >> Açık dizin listeleme testi:")
    dizin_yollari = ["/uploads", "/files", "/backup", "/logs", "/tmp", "/data", "/static"]
    for yol in dizin_yollari:
        hedef = url.rstrip("/") + yol
        try:
            cevap = requests.get(hedef, timeout=5)
            if cevap.status_code == 200 and "Index of" in cevap.text:
                print(f"  [!] Açık dizin listeleme: {hedef}")
                sonuclar.append({
                    "tur": "Security Misconfiguration",
                    "detay": f"Açık dizin listeleme tespit edildi: {hedef}"
                })
            else:
                print(f"  [✓] Kapalı: {hedef}")
        except Exception as e:
            print(f"  [!] Bağlantı hatası: {hedef} → {e}")

    # --- TEST 2: Hassas dosya ifşası ---
    print("\n  >> Hassas dosya ifşası testi:")
    hassas_dosyalar = [
        "/.env",
        "/config.php",
        "/config.yml",
        "/config.json",
        "/.git/config",
        "/wp-config.php",
        "/database.sql",
        "/backup.zip",
        "/robots.txt",
        "/sitemap.xml",
    ]
    for dosya in hassas_dosyalar:
        hedef = url.rstrip("/") + dosya
        try:
            cevap = requests.get(hedef, timeout=5)
            if cevap.status_code == 200:
                # İçerik hassas veri içeriyor mu?
                hassas_ifadeler = [
                    "DB_PASSWORD", "APP_KEY", "SECRET", "PASSWORD",
                    "database", "mysqli", "<?php", "mysql_connect"
                ]
                bulunan = [i for i in hassas_ifadeler if i.lower() in cevap.text.lower()]
                if bulunan:
                    print(f"  [!] Hassas dosya açığa çıkmış: {hedef} → {bulunan}")
                    sonuclar.append({
                        "tur": "Security Misconfiguration - Hassas Dosya",
                        "detay": f"Hassas dosya erişilebilir: {hedef} | İçerik: {bulunan}"
                    })
                else:
                    print(f"  [~] Dosya mevcut ama hassas içerik bulunamadı: {hedef}")
            else:
                print(f"  [✓] Erişilemiyor: {hedef} → HTTP {cevap.status_code}")
        except Exception as e:
            print(f"  [!] Bağlantı hatası: {hedef} → {e}")

    # --- TEST 3: Hata mesajı sızıntısı ---
    print("\n  >> Hata mesajı sızıntısı testi:")
    hata_yollari = [
        "/xyz_olmayan_sayfa_12345",
        "/index.php?id=HATA_TESTI",
        "/?q=<INVALID>",
    ]
    hata_ifadeleri = [
        "stack trace", "traceback", "fatal error", "warning:",
        "mysql", "syntax error", "exception", "undefined variable",
        "on line", "php error", "django", "debug"
    ]
    for yol in hata_yollari:
        hedef = url.rstrip("/") + yol
        try:
            cevap = requests.get(hedef, timeout=5)
            bulunan = [i for i in hata_ifadeleri if i in cevap.text.lower()]
            if bulunan:
                print(f"  [!] Hata mesajı sızıntısı: {hedef} → {bulunan}")
                sonuclar.append({
                    "tur": "Security Misconfiguration - Hata Mesajı",
                    "detay": f"Sistem hata detayları açığa çıkıyor: {hedef} | Bulunan: {bulunan}"
                })
            else:
                print(f"  [✓] Temiz: {hedef}")
        except Exception as e:
            print(f"  [!] Bağlantı hatası: {hedef} → {e}")

    # --- TEST 4: Güvensiz HTTP başlıkları ---
    print("\n  >> HTTP güvenlik başlıkları kontrolü:")
    try:
        cevap = requests.get(url, timeout=5)
        headers = cevap.headers

        guvenlik_basliklar = {
            "X-Frame-Options": "Clickjacking saldırılarına karşı koruma",
            "X-Content-Type-Options": "MIME sniffing saldırılarına karşı koruma",
            "Strict-Transport-Security": "HTTPS zorunluluğu (HSTS)",
            "Content-Security-Policy": "XSS ve injection saldırılarına karşı koruma",
            "X-XSS-Protection": "Tarayıcı tabanlı XSS koruması",
            "Referrer-Policy": "Referrer bilgisi sızıntısına karşı koruma",
        }

        for baslik, aciklama in guvenlik_basliklar.items():
            if baslik not in headers:
                print(f"  [!] Eksik güvenlik başlığı: {baslik} — {aciklama}")
                sonuclar.append({
                    "tur": "Security Misconfiguration - Eksik HTTP Başlığı",
                    "detay": f"'{baslik}' başlığı eksik: {aciklama}"
                })
            else:
                print(f"  [✓] Mevcut: {baslik}")

        # Server başlığı bilgi sızıntısı
        if "Server" in headers:
            print(f"  [~] Server başlığı bilgi sızdırıyor: {headers['Server']}")
            sonuclar.append({
                "tur": "Security Misconfiguration - Bilgi Sızıntısı",
                "detay": f"Server başlığı sistem bilgisi açığa çıkarıyor: {headers['Server']}"
            })

    except Exception as e:
        print(f"  [!] HTTP başlık kontrolü hatası: {e}")

    return sonuclar


if __name__ == "__main__":
    sonuclar = security_misconfiguration_test("http://testphp.vulnweb.com")
    print(f"\n--- SONUÇ: {len(sonuclar)} adet Security Misconfiguration açığı bulundu ---")
    for s in sonuclar:
        print(f"  • [{s['tur']}] {s['detay']}")
