#!/usr/bin/env python3
import sys, os, subprocess, ipaddress, tempfile
from soc_config import load_soc_config

config = load_soc_config()
SERVER_IP = config.get("SERVER_IP", "")

CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

WHITELIST = [
    "127.0.0.1",
    SERVER_IP
] if SERVER_IP else ["127.0.0.1"]

# TR: Yasaklanacak IP adresini arguman olarak al
# EN: Get the IP address to ban as an argument
if len(sys.argv) < 2:
    print("Kullanim: nginx-ban-ip.py <ip>")
    sys.exit(1)

ip_str = sys.argv[1]

# TR: IP adresi dogrulama
# EN: IP address validation
try:
    ip_obj = ipaddress.ip_address(ip_str)
    
    # TR: Whitelist kontrolü
    # EN: Whitelist check
    if any(ip_str == w for w in WHITELIST):
        print(f"BEYAZ LİSTE IP atlandı / Skipped: {ip_str}")
        sys.exit(0)
        
    # TR: Cloudflare kontrolü
    # EN: Cloudflare check
    cf_networks = [ipaddress.ip_network(r) for r in CLOUDFLARE_RANGES]
    if any(ip_obj in net for net in cf_networks):
        print(f"CLOUDFLARE IP atlandı / Skipped: {ip_str}")
        sys.exit(0)

    # TR: Private IP'leri engellemeye calisiyorsak hata ver
    # EN: Error if trying to ban private IPs
    if ip_obj.is_private or ip_obj.is_loopback:
        print(f"Hata: Yerel veya ozel IP adresi banlanamaz: {ip_str}")
        sys.exit(1)
except ValueError:
    print(f"Hata: Gecersiz IP adresi: {ip_str}")
    sys.exit(1)

# TR: Nginx engellenen IP'ler dosyasinin konumu
# EN: Location of the Nginx blocked IPs file
fn = "/etc/nginx/snippets/blocked-ips.conf"
target_dir = os.path.dirname(fn)
if not os.path.exists(target_dir):
    os.makedirs(target_dir, exist_ok=True)

# TR: Dosya varsa oku, yoksa varsayilan basligi olustur
# EN: Read file if it exists, otherwise create default header
content = ""
if os.path.exists(fn):
    with open(fn, 'r') as f:
        content = f.read()
else:
    content = "# SOC Blocked IPs\n"

deny_rule = f"deny {ip_str};"

# TR: IP zaten yasaklanmissa islemi iptal et
# EN: If the IP is already banned, exit the process
if deny_rule in content:
    print(f"IP zaten yasakli: {ip_str}")
    sys.exit(0)

# TR: Eski satirlari oku, 'allow all' haric tut ve yeni yasagi ekle
# EN: Read old lines, exclude 'allow all', and append the new ban
lines = [l for l in content.split("\n") if l.strip() not in ("allow all;", "") and deny_rule not in l]
lines.append(deny_rule)
lines.append("allow all;")

# TR: Atomic Yazma (Atomik Write) - Yarış durumlarını (Race Condition) önlemek için
# EN: Atomic Write - To prevent race conditions
fd, temp_path = tempfile.mkstemp(dir=target_dir, text=True)
try:
    with os.fdopen(fd, 'w') as tmp:
        tmp.write("\n".join(lines) + "\n")
    # Dosya izinlerini koru (644)
    os.chmod(temp_path, 0o644)
    os.replace(temp_path, fn)
except Exception as e:
    if os.path.exists(temp_path):
        os.remove(temp_path)
    print(f"Yazma hatasi: {e}")
    sys.exit(1)

# TR: Nginx'i yeniden baslat (systemctl daha sagliklidir)
# EN: Reload Nginx (systemctl is more robust)
subprocess.run(["systemctl", "reload", "nginx"])
print(f"Basariyla banlandi: {ip_str}")
