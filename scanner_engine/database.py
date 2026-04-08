import sqlite3

def veritabani_baglant():
    """
    SQLite veritabanına bağlantı kurar.
    Döndürür: bağlantı nesnesi
    """
    baglanti = sqlite3.connect("siber_savascılar.db")
    return baglanti

def tablolari_olustur():
    """
    Veritabanında gerekli tabloları oluşturur.
    - taramalar: yapılan taramaların kayıtları
    - zafiyetler: bulunan güvenlik açıkları
    """
    baglanti = veritabani_baglant()
    cursor = baglanti.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS taramalar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hedef_url TEXT,
            durum TEXT,
            baslangic_zamani TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS zafiyetler (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tarama_id INTEGER,
            zafiyet_turu TEXT,
            detay TEXT,
            FOREIGN KEY (tarama_id) REFERENCES taramalar(id)
        )
    """)

    baglanti.commit()
    baglanti.close()
    print("Veritabanı ve tablolar hazır!")

tablolari_olustur()