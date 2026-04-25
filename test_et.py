from motor.senaryo_okuyucu import senaryo_oku
from motor.ozel_tarama_motoru import ozel_senaryo_calistir

# 1. Okunacak YAML dosyasının yolu
dosya_yolu = "senaryolar/ornek_senaryo.yaml"

# 2. Test edeceğimiz güvenli bir hedef site
hedef_site = "http://example.com"

print("1. Aşama: YAML Senaryosu Okunuyor...")
okunan_veri = senaryo_oku(dosya_yolu)
print(f"Senaryo Adı: {okunan_veri.get('info', {}).get('name')}\n")

print(f"2. Aşama: {hedef_site} hedefine test başlatılıyor...")
sonuclar = ozel_senaryo_calistir(okunan_veri, hedef_site)

print("\n--- TEST SONUÇLARI ---")
if sonuclar:
    for bulgu in sonuclar:
        print(f"[!] BULGU: {bulgu['bulgu']} -> {bulgu['detay']}")
else:
    print("[-] Herhangi bir eşleşme/bulgu tespit edilmedi.")