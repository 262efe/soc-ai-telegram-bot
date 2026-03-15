#!/bin/bash

# TR: Yasagi kaldirilacak IP adresini arguman olarak al
# EN: Get the IP address to be unbanned as an argument
IP="$1"
# TR: Nginx engellenen IP'ler dosyasinin konumu
# EN: Location of the Nginx blocked IPs file
FILE=/etc/nginx/snippets/blocked-ips.conf

# TR: Hardened Python scriptini kullanarak unban islemini gerçekleştir
# EN: Execute the unbanning process using the hardened Python script
python3 /usr/local/bin/nginx-unban-ip.py "$IP"
