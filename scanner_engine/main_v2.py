from port_scanner import port_tara
from vuln_scanner import sqli_test, xss_test
from access_control_scanner import broken_access_control_test
from misconfig_scanner import security_misconfiguration_test
from sensitive_data_scanner import sensitive_data_exposure_test
from database import veritabani_baglant, tablolari_olustur
import datetime

def tarama_baslat(hedef_url):
    """
    Tüm tarama modüllerini sırasıyla çalıştıran ana orkestratör.

    Çalışan testler:
        - Port Tarama (Nmap)
        - SQL Injection
        - XSS (Cross-Site Scripting)
        - Broken Access Control (OWASP A01)
        - Security Misconfiguration (OWASP A05)
        - Sensitive Data Exposure (OWASP A02)

    Parametreler:
        hedef_url (str): Taranacak hedef URL veya IP adresi
    """
    tablolari_olustur()
    baglanti = veritabani_baglant()
    cursor = baglanti.cursor()

    simdi = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO taramalar (hedef_url, durum, baslangic_zamani)
        VALUES (?, ?, ?)
    """, (hedef_url, "Başladı", simdi))
    baglanti.commit()
    tarama_id = cursor.lastrowid

    print(f"\n{'='*50}")
    print(f"  SİBER SAVAŞÇILAR — TAM TARAMA BAŞLIYOR")
    print(f"  Hedef : {hedef_url}")
    print(f"  Zaman : {simdi}")
    print(f"  ID    : {tarama_id}")
    print(f"{'='*50}")

    tum_sonuclar = []

    # 1. Port tarama
    print("\n[1/6] Port taraması başlıyor...")
    try:
        acik_portlar = port_tara(hedef_url)
        print(f"  Açık port sayısı: {len(acik_portlar)}")
    except Exception as e:
        print(f"  [!] Port tarama hatası: {e}")
        acik_portlar = []

    # 2. SQL Injection testi
    print("\n[2/6] SQL Injection testi başlıyor...")
    try:
        sqli_sonuclar = sqli_test(f"http://{hedef_url}")
        tum_sonuclar.extend(sqli_sonuclar)
    except Exception as e:
        print(f"  [!] SQLi test hatası: {e}")

    # 3. XSS testi
    print("\n[3/6] XSS testi başlıyor...")
    try:
        xss_sonuclar = xss_test(f"http://{hedef_url}")
        tum_sonuclar.extend(xss_sonuclar)
    except Exception as e:
        print(f"  [!] XSS test hatası: {e}")

    # 4. Broken Access Control testi (YENİ)
    print("\n[4/6] Broken Access Control testi başlıyor...")
    try:
        bac_sonuclar = broken_access_control_test(f"http://{hedef_url}")
        tum_sonuclar.extend(bac_sonuclar)
    except Exception as e:
        print(f"  [!] Broken Access Control test hatası: {e}")

    # 5. Security Misconfiguration testi (YENİ)
    print("\n[5/6] Security Misconfiguration testi başlıyor...")
    try:
        misconfig_sonuclar = security_misconfiguration_test(f"http://{hedef_url}")
        tum_sonuclar.extend(misconfig_sonuclar)
    except Exception as e:
        print(f"  [!] Misconfiguration test hatası: {e}")

    # 6. Sensitive Data Exposure testi (YENİ)
    print("\n[6/6] Sensitive Data Exposure testi başlıyor...")
    try:
        sde_sonuclar = sensitive_data_exposure_test(f"http://{hedef_url}")
        tum_sonuclar.extend(sde_sonuclar)
    except Exception as e:
        print(f"  [!] Sensitive Data test hatası: {e}")

    # Tüm sonuçları veritabanına kaydet
    for zafiyet in tum_sonuclar:
        cursor.execute("""
            INSERT INTO zafiyetler (tarama_id, zafiyet_turu, detay)
            VALUES (?, ?, ?)
        """, (tarama_id, zafiyet["tur"], zafiyet["detay"]))

    cursor.execute("UPDATE taramalar SET durum = ? WHERE id = ?", ("Bitti", tarama_id))
    baglanti.commit()
    baglanti.close()

    # Özet rapor
    print(f"\n{'='*50}")
    print(f"  TARAMA TAMAMLANDI!")
    print(f"  Açık port sayısı : {len(acik_portlar)}")
    print(f"  Bulunan zafiyet  : {len(tum_sonuclar)}")
    print(f"{'='*50}")

    if tum_sonuclar:
        print("\n  Bulunan Açıklar:")
        for z in tum_sonuclar:
            print(f"  [!] {z['tur']}: {z['detay']}")
    else:
        print("\n  Herhangi bir açık tespit edilmedi.")

    return tum_sonuclar


if __name__ == "__main__":
    tarama_baslat("scanme.nmap.org")
