import requests

def ozel_senaryo_calistir(senaryo_verisi, hedef_url):
    """Okunan senaryodaki kuralları hedef URL üzerinde test eder."""
    bulgular = []
    
    # Eğer okuma aşamasında hata olduysa işlemi durdur
    if "hata" in senaryo_verisi:
        return senaryo_verisi
        
    istekler = senaryo_verisi.get('requests', [])
    
    for istek in istekler:
        metod = istek.get('method', 'GET')
        yollar = istek.get('path', [])
        eslestiriciler = istek.get('matchers', [])
        
        for yol in yollar:
            # Senaryodaki {{target_url}} kısmını gerçek hedefle değiştir
            tam_url = yol.replace("{{target_url}}", hedef_url.rstrip('/'))
            
            try:
                # Hedefe istek atılıyor
                cevap = requests.request(metod, tam_url, timeout=5)
                
                # Gelen cevabı kurallarla karşılaştır
                for kural in eslestiriciler:
                    # Durum kodu kontrolü (örn: 200 mü döndü?)
                    if kural['type'] == 'status' and cevap.status_code in kural['status']:
                        bulgular.append({
                            "url": tam_url,
                            "bulgu": "Durum Kodu Eşleşmesi",
                            "detay": f"Status: {cevap.status_code}"
                        })
                        
                    # Kelime kontrolü (örn: Sayfada 'DB_PASSWORD' geçiyor mu?)
                    elif kural['type'] == 'word':
                        for kelime in kural['words']:
                            if kelime in cevap.text:
                                bulgular.append({
                                    "url": tam_url,
                                    "bulgu": "Hassas Veri Sızıntısı",
                                    "detay": f"Bulunan kelime: {kelime}"
                                })
            except Exception as e:
                print(f"Hedefe ulaşılamadı: {tam_url} - Hata: {e}")
                
    return bulgular