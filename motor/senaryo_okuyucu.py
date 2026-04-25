import yaml
import os

def senaryo_oku(dosya_yolu):
    """YAML dosyasını okur ve Python'un anlayacağı veriye çevirir."""
    if not os.path.exists(dosya_yolu):
        return {"hata": "Dosya bulunamadı."}
        
    try:
        with open(dosya_yolu, 'r', encoding='utf-8') as dosya:
            senaryo_verisi = yaml.safe_load(dosya)
            return senaryo_verisi
    except yaml.YAMLError as e:
        return {"hata": f"YAML format hatası: {e}"}