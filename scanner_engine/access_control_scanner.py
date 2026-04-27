import requests

def broken_access_control_test(url):
    """
    OWASP A01: Broken Access Control (Bozuk Erişim Kontrolü) testini gerçekleştirir.
    
    Yönetici paneli ve hassas sayfalara yetkisiz erişim denenebiliyor mu kontrol eder.
    URL manipülasyonu ile başka kullanıcı verilerine erişilebiliyor mu test eder.

    Parametreler:
        url (str): Test edilecek web adresi (örn: http://example.com)

    Döndürür:
        sonuclar (list): Bulunan açıkların listesi
    """

    # Yönetici ve hassas sayfa yolları
    admin_yollar = [
        "/admin",
        "/admin/dashboard",
        "/admin/users",
        "/administrator",
        "/panel",
        "/yonetim",
        "/manager",
        "/superuser",
        "/wp-admin",
        "/phpmyadmin",
    ]

    # URL manipülasyonu ile farklı kullanıcı ID'leri
    idor_yollar = [
        "/user?id=1",
        "/user?id=2",
        "/account?id=1",
        "/profile?user=admin",
        "/api/users/1",
        "/api/users/2",
    ]

    sonuclar = []

    print("\n[*] Broken Access Control testi başlıyor...")

    # Admin panel erişim testi
    print("\n  >> Yetkisiz yönetici paneli erişim testi:")
    for yol in admin_yollar:
        hedef = url.rstrip("/") + yol
        try:
            cevap = requests.get(hedef, timeout=5, allow_redirects=False)
            # 200 dönüyorsa direkt erişim var demektir
            if cevap.status_code == 200:
                print(f"  [!] ERİŞİM AÇIĞI: {hedef} → HTTP {cevap.status_code}")
                sonuclar.append({
                    "tur": "Broken Access Control",
                    "detay": f"Yetkisiz erişim mümkün: {hedef} (HTTP 200)"
                })
            # 403 veya 401 dönüyorsa sayfa var ama korumalı
            elif cevap.status_code in [401, 403]:
                print(f"  [✓] Korumalı: {hedef} → HTTP {cevap.status_code}")
            else:
                print(f"  [-] Bulunamadı: {hedef} → HTTP {cevap.status_code}")
        except Exception as e:
            print(f"  [!] Bağlantı hatası: {hedef} → {e}")

    # IDOR (Insecure Direct Object Reference) testi
    print("\n  >> IDOR (Doğrudan Nesne Referansı) testi:")
    for yol in idor_yollar:
        hedef = url.rstrip("/") + yol
        try:
            cevap = requests.get(hedef, timeout=5)
            if cevap.status_code == 200:
                # Cevap içinde hassas veri işaretleri
                hassas_kelimeler = ["email", "password", "phone", "address", "token", "username"]
                bulunan = [k for k in hassas_kelimeler if k in cevap.text.lower()]
                if bulunan:
                    print(f"  [!] IDOR açığı olabilir: {hedef} → Hassas alanlar: {bulunan}")
                    sonuclar.append({
                        "tur": "IDOR (Broken Access Control)",
                        "detay": f"Hassas veri açığa çıkmış olabilir: {hedef} → {bulunan}"
                    })
                else:
                    print(f"  [✓] Temiz: {hedef}")
            else:
                print(f"  [-] Erişilemiyor: {hedef} → HTTP {cevap.status_code}")
        except Exception as e:
            print(f"  [!] Bağlantı hatası: {hedef} → {e}")

    return sonuclar


if __name__ == "__main__":
    sonuclar = broken_access_control_test("http://testphp.vulnweb.com")
    print(f"\n--- SONUÇ: {len(sonuclar)} adet Broken Access Control açığı bulundu ---")
    for s in sonuclar:
        print(f"  • [{s['tur']}] {s['detay']}")
