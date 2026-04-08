import nmap
import os

# Nmap'in Windows'taki kurulum yolunu Python'a tanıtıyoruz
os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"

def port_tara(hedef):
    """
    Verilen hedefteki açık portları tarar.
    
    Parametreler:
        hedef (str): Taranacak URL veya IP adresi
    
    Döndürür:
        acik_portlar (list): Açık bulunan port numaraları
    
    Taranan portlar: 80 (HTTP), 443 (HTTPS), 8080 (Web), 3306 (MySQL)
    """
    tarayici = nmap.PortScanner(nmap_search_path=(r'C:\Program Files (x86)\Nmap\nmap.exe',))
    
    print(f"\n{hedef} taranıyor, lütfen bekle...")
    tarayici.scan(hedef, '80,443,8080,3306', '-T4')
    
    acik_portlar = []
    
    for host in tarayici.all_hosts():
        for port in tarayici[host]['tcp']:
            durum = tarayici[host]['tcp'][port]['state']
            if durum == 'open':
                print(f"  Port {port} → AÇIK")
                acik_portlar.append(port)
            else:
                print(f"  Port {port} → kapalı")
    
    return acik_portlar

if __name__ == "__main__":
    port_tara("scanme.nmap.org")