from port_scanner import port_tara
from vuln_scanner import sqli_test, xss_test
from database import veritabani_baglant, tablolari_olustur
import datetime

def tarama_baslat(hedef_url):
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

    print(f"\n{'='*40}")
    print(f"Hedef: {hedef_url}")
    print(f"Tarama ID: {tarama_id}")
    print(f"{'='*40}")

    # Port tara
    print("\n[*] Port taraması başlıyor...")
    acik_portlar = port_tara(hedef_url)

    # Zafiyet tara
    print("\n[*] SQLi testi başlıyor...")
    sqli_sonuclar = sqli_test(f"http://{hedef_url}")
    
    print("\n[*] XSS testi başlıyor...")
    xss_sonuclar = xss_test(f"http://{hedef_url}")

    # Zafiyetleri DB'ye kaydet
    tum_sonuclar = sqli_sonuclar + xss_sonuclar
    for zafiyet in tum_sonuclar:
        cursor.execute("""
            INSERT INTO zafiyetler (tarama_id, zafiyet_turu, detay)
            VALUES (?, ?, ?)
        """, (tarama_id, zafiyet["tur"], zafiyet["detay"]))

    cursor.execute("UPDATE taramalar SET durum = ? WHERE id = ?", ("Bitti", tarama_id))
    baglanti.commit()
    baglanti.close()

    print(f"\n{'='*40}")
    print(f"TARAMA TAMAMLANDI!")
    print(f"Açık port: {len(acik_portlar)}")
    print(f"Bulunan zafiyet: {len(tum_sonuclar)}")
    print(f"{'='*40}")

tarama_baslat("scanme.nmap.org")