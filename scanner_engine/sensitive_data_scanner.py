import requests
import re

def sensitive_data_exposure_test(url):
    """
    OWASP A02: Cryptographic Failures / Sensitive Data Exposure
    (Hassas Veri İfşası) testini gerçekleştirir.

    HTTP üzerinden veri iletimi, açık şifreler, e-posta adresleri,
    kredi kartı numaraları ve API anahtarları gibi hassas verilerin
    sayfa içinde görünür olup olmadığını kontrol eder.

    Parametreler:
        url (str): Test edilecek web adresi (örn: http://example.com)

    Döndürür:
        sonuclar (list): Bulunan açıkların listesi
    """

    sonuclar = []

    print("\n[*] Sensitive Data Exposure testi başlıyor...")

    # --- TEST 1: HTTP mi HTTPS mi? ---
    print("\n  >> Protokol güvenlik kontrolü:")
    if url.startswith("http://"):
        print(f"  [!] Site HTTP kullanıyor — veriler şifrelenmeden iletiliyor: {url}")
        sonuclar.append({
            "tur": "Sensitive Data Exposure - Şifresiz İletişim",
            "detay": f"Site HTTP protokolü kullanıyor, HTTPS zorunlu kılınmamış: {url}"
        })
    else:
        print(f"  [✓] HTTPS kullanılıyor: {url}")

    # --- TEST 2: Sayfa içeriğinde hassas veri arama ---
    print("\n  >> Sayfa içeriği hassas veri taraması:")

    taranacak_sayfalar = [
        "/",
        "/login",
        "/register",
        "/signup",
        "/contact",
        "/api",
        "/api/users",
        "/search?q=test",
    ]

    # Hassas veri pattern'leri (Regex)
    hassas_patternler = {
        "E-posta adresi": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "Olası şifre ifadesi": r"(password|passwd|pwd)\s*[:=]\s*\S+",
        "API anahtarı": r"(api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['\"]?\w{16,}",
        "Kredi kartı numarası": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "JWT Token": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "IP adresi (dahili)": r"\b(192\.168|10\.\d{1,3}|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b",
    }

    for sayfa in taranacak_sayfalar:
        hedef = url.rstrip("/") + sayfa
        try:
            cevap = requests.get(hedef, timeout=5)
            if cevap.status_code != 200:
                continue

            print(f"\n  Taranan sayfa: {hedef}")
            sayfa_bulgu = False

            for tur, pattern in hassas_patternler.items():
                eslesmeler = re.findall(pattern, cevap.text, re.IGNORECASE)
                if eslesmeler:
                    # İlk 2 eşleşmeyi göster (gizlilik için hepsini değil)
                    ornek = eslesmeler[:2]
                    print(f"  [!] {tur} bulundu: {ornek}")
                    sonuclar.append({
                        "tur": f"Sensitive Data Exposure - {tur}",
                        "detay": f"Sayfa: {hedef} | Örnek: {ornek}"
                    })
                    sayfa_bulgu = True

            if not sayfa_bulgu:
                print(f"  [✓] Hassas veri bulunamadı")

        except Exception as e:
            print(f"  [!] Bağlantı hatası: {hedef} → {e}")

    # --- TEST 3: Login formunda HTTPS kontrolü ---
    print("\n  >> Login formu güvenlik kontrolü:")
    login_yollar = ["/login", "/signin", "/giris", "/kullanici-girisi"]
    for yol in login_yollar:
        hedef = url.rstrip("/") + yol
        try:
            cevap = requests.get(hedef, timeout=5)
            if cevap.status_code == 200:
                # Form action HTTP mi kullanıyor?
                if 'action="http://' in cevap.text or "action='http://" in cevap.text:
                    print(f"  [!] Login formu HTTP üzerinden gönderiyor: {hedef}")
                    sonuclar.append({
                        "tur": "Sensitive Data Exposure - Güvensiz Form",
                        "detay": f"Login formu şifresiz HTTP ile veri gönderiyor: {hedef}"
                    })
                elif "password" in cevap.text.lower():
                    print(f"  [~] Login formu bulundu, protokol doğrulanamadı: {hedef}")
                else:
                    print(f"  [✓] Temiz: {hedef}")
        except Exception as e:
            print(f"  [!] Bağlantı hatası: {hedef} → {e}")

    return sonuclar


if __name__ == "__main__":
    sonuclar = sensitive_data_exposure_test("http://testphp.vulnweb.com")
    print(f"\n--- SONUÇ: {len(sonuclar)} adet Sensitive Data Exposure açığı bulundu ---")
    for s in sonuclar:
        print(f"  • [{s['tur']}] {s['detay']}")
