#!/bin/bash

# TR: Yasaklanacak IP adresini arguman olarak al
# EN: Get the IP address to ban as an argument
IP="$1"
# TR: Nginx engellenen IP'ler dosyasinin konumu
# EN: Location of the Nginx blocked IPs file
FILE=/etc/nginx/snippets/blocked-ips.conf

# TR: Hardened Python scriptini kullanarak ban islemini gerçekleştir
# EN: Execute the banning process using the hardened Python script
python3 /usr/local/bin/nginx-ban-ip.py "$IP"
