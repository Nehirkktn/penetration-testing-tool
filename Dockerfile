# ─────────────────────────────────────────────────────────────────────
#  Sızma Testi Otomasyon Aracı — Docker İmajı
#  Geliştirici Ekibi: Siber Savaşçılar
#  Fırat Üniversitesi Yazılım Mühendisliği Temelleri Dersi
# ─────────────────────────────────────────────────────────────────────

# Python 3.13 imajını kullanıyoruz
FROM python:3.13-slim

# Konteyner içindeki çalışma dizinini ayarlıyoruz
WORKDIR /app

# GÜVENLİK ARAÇLARINI KURUYORUZ (Kritik Adım)
# Sızma testi aracının arka planda tarama yapabilmesi için nmap ve sqlmap yüklüyoruz
RUN apt-get update && apt-get install -y \
    nmap \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# requirements dosyasını kopyalayıp Python kütüphanelerini kuruyoruz
# (Önce sadece requirements'i kopyalamak, kod değişikliklerinde cache'i bozmaz)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Projenin tüm kodlarını kopyalıyoruz
COPY . .

# Veri ve rapor klasörleri için kalıcı volume noktaları
VOLUME ["/app/data", "/app/reports"]

# Flask API portunu açıyoruz
EXPOSE 5000

# Uygulamayı başlatma komutu
# host=0.0.0.0 olarak server.py'de zaten ayarlı (Docker'dan dışarı açılması için)
CMD ["python", "-m", "siber_savascilar.api.server"]
