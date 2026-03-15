#!/bin/bash
# 
# Automated Installation Script
# 

# Colors
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
echo -e "${GREEN}  This system was created by efealtintas.com.           ${NC}"
echo -e "${BLUE}========================================================================${NC}\n"

echo -e "⚡ Installation started...\n"

# Create directories
echo -e "[1/6] Creating system directories..."
sudo mkdir -p /var/lib/soc
sudo mkdir -p /etc/soc

# Check dependencies and install
echo -e "[2/6] Checking package dependencies..."
if command -v apt-get >/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3 python3-pip nginx sqlite3 curl
elif command -v dnf >/dev/null; then
    sudo dnf install -y -q python3 python3-pip nginx sqlite3 curl
fi

# Install Python packages
echo -e "[3/6] Installing Python modules..."
if [ -f "requirements.txt" ]; then
    sudo pip3 install -q -r requirements.txt --break-system-packages
else
    sudo pip3 install -q requests pyTelegramBotAPI psutil --break-system-packages
fi

# Copy files
echo -e "[4/6] Copying SOC components to system directories..."
sudo cp soc-*.py /usr/local/bin/
sudo cp soc_config.py /usr/local/bin/
sudo cp nginx-*.sh nginx-*.py /usr/local/bin/ 2>/dev/null || true
sudo chmod +x /usr/local/bin/soc-*
sudo chmod +x /usr/local/bin/nginx-* 2>/dev/null || true

if [ -f "config.env" ]; then
    sudo cp config.env /etc/soc/config.env
else
    sudo cp config.env.example /etc/soc/config.env
    echo -e "${CYAN}INFO: config.env not found. Example file copied. Please edit /etc/soc/config.env after installation.${NC}"
fi

# Start database
echo -e "[5/6] Starting database..."
sudo python3 /usr/local/bin/soc-db-init.py

# Install services
echo -e "[6/6] Installing background services..."
if [ -f "soc-bot-listener.service" ]; then
    sudo cp soc-bot-listener.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable soc-bot-listener
    sudo systemctl restart soc-bot-listener
else
    echo -e "${CYAN}WARNING: Service file (soc-bot-listener.service) not found, manual installation may be required.${NC}"
fi

echo -e "\n${GREEN}✔ Installation completed!${NC}"
echo -e "To monitor logs: ${CYAN}journalctl -f -u soc-bot-listener${NC}"
echo -e "\nTo ensure the system works, make sure to enter API Key and Token values in '/etc/soc/config.env'"
