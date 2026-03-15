#!/bin/bash
# 
# Otomatik Kurulum Scripti
# 

# Renkler
GREEN="\033[0;32m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
NC="\033[0m" # No Color

clear

echo -e "${CYAN}"
cat << "EOF"
  ____   ___   ____       _    ___   _____    _                                
 / ___| / _ \ / ___|     / \  |_ _| |_   _|__| | ___  __ _ _ __ __ _ _ __ ___  
 \___ \| | | | |   _____/ _ \  | |    | |/ _ \ |/ _ \/ _` | '__/ _` | '_ ` _ \ 
  ___) | |_| | |__|_____/ ___ \| |    | |  __/ |  __/ (_| | | | (_| | | | | | |
 |____/ \___/ \____|   /_/   \_\___|  |_|\___|_|\___|\__, |_|  \__,_|_| |_| |_|
                                                     |___/                     
EOF
echo -e "${NC}"

echo -e "${BLUE}========================================================================${NC}"
echo -e "${GREEN}  Bu sistem efealtintas.com tarafindan hazirlanmistir.  ${NC}"
echo -e "${GREEN}  This system was created by efealtintas.com.           ${NC}"
echo -e "${BLUE}========================================================================${NC}\n"

echo -e "⚡ Kurulum basliyor...\n"

# Gerekli dizinleri olustur
echo -e "[1/6] Sistem dizinleri olusturuluyor..."
sudo mkdir -p /var/lib/soc
sudo mkdir -p /etc/soc

# Bagimliliklari kontrol et ve kur
echo -e "[2/6] Paket bagimliliklari kontrol ediliyor..."
if command -v apt-get >/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3 python3-pip nginx sqlite3 curl
elif command -v dnf >/dev/null; then
    sudo dnf install -y -q python3 python3-pip nginx sqlite3 curl
fi

# Python paketlerini kur
echo -e "[3/6] Python modulleri kuruluyor..."
if [ -f "requirements.txt" ]; then
    sudo pip3 install -q -r requirements.txt
else
    sudo pip3 install -q requests pyTelegramBotAPI psutil
fi

# Dosyalari yerlestir
echo -e "[4/6] SOC bilesenleri sistem dizinlerine kopyalaniyor..."
sudo cp soc-*.py /usr/local/bin/
sudo cp soc_config.py /usr/local/bin/
sudo cp nginx-*.sh nginx-*.py /usr/local/bin/ 2>/dev/null || true
sudo chmod +x /usr/local/bin/soc-*
sudo chmod +x /usr/local/bin/nginx-* 2>/dev/null || true

if [ -f "config.env" ]; then
    sudo cp config.env /etc/soc/config.env
else
    sudo cp config.env.example /etc/soc/config.env
    echo -e "${CYAN}BILGI: config.env bulunamadi. Ornek dosya kopyalandi. Kurulumdan sonra /etc/soc/config.env dosyasini duzenlemelisiniz.${NC}"
fi

# Veritabanini baslat
echo -e "[5/6] Veritabani baslatiliyor..."
sudo python3 /usr/local/bin/soc-db-init.py

# Servisleri kur ve baslat
echo -e "[6/6] Arka plan servisleri kuruluyor ve baslatiliyor..."
if [ -f "soc-bot-listener.service" ]; then
    sudo cp soc-bot-listener.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable soc-bot-listener
    sudo systemctl restart soc-bot-listener
else
    echo -e "${CYAN}UYARI: Servis dosyasi (soc-bot-listener.service) bulunamadi, manuel kurmaniz gerekebilir.${NC}"
fi

echo -e "\n${GREEN}✔ Kurulum Tamamlandi!${NC}"
echo -e "Loglari izlemek icin: ${CYAN}journalctl -f -u soc-bot-listener${NC}"
echo -e "\nSistemin calismasi icin '/etc/soc/config.env' dosyasina API Key ve Token degerlerini girdiginizden emin olun."
