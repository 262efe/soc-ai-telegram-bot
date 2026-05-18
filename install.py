#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess

def run_cmd(cmd, shell=False):
    subprocess.run(cmd, shell=shell)

def main():
    if os.geteuid() != 0:
        print("Please run as root (sudo python3 install.py)")
        sys.exit(1)

    print("\033[0;36m")
    print(r"""
  ____   ___   ____       _    ___   _____    _                                
 / ___| / _ \ / ___|     / \  |_ _| |_   _|__| | ___  __ _ _ __ __ _ _ __ ___  
 \___ \| | | | |   _____/ _ \  | |    | |/ _ \ |/ _ \/ _` | '__/ _` | '_ ` _ \ 
  ___) | |_| | |__|_____/ ___ \| |    | |  __/ |  __/ (_| | | | (_| | | | | | |
 |____/ \___/ \____|   /_/   \_\___|  |_|\___|_|\___|\__, |_|  \__,_|_| |_| |_|
                                                     |___/                     
    """)
    print("\033[0m")
    print("\033[0;34m========================================================================\033[0m")
    print("\033[0;32m  This system was created by efealtintas.com.           \033[0m")
    print("\033[0;34m========================================================================\033[0m\n")

    print("⚡ Installation started...\n")

    print("[1/6] Creating system directories...")
    os.makedirs("/var/lib/soc", exist_ok=True)
    os.makedirs("/etc/soc", exist_ok=True)

    print("[2/6] Checking package dependencies...")
    if shutil.which("apt-get"):
        run_cmd("apt-get update -qq", shell=True)
        run_cmd("apt-get install -y -qq python3 python3-pip nginx sqlite3 curl", shell=True)
    elif shutil.which("dnf"):
        run_cmd("dnf install -y -q python3 python3-pip nginx sqlite3 curl", shell=True)

    print("[3/6] Installing Python modules...")
    if os.path.exists("requirements.txt"):
        run_cmd("pip3 install -q -r requirements.txt --break-system-packages", shell=True)
    else:
        run_cmd("pip3 install -q requests pyTelegramBotAPI psutil --break-system-packages", shell=True)

    print("[4/6] Copying SOC components to system directories...")
    # Copy from all subdirectories
    run_cmd("cp core/*.py bot/*.py engine/*.py actions/*.py scripts/*.py /usr/local/bin/", shell=True)
    run_cmd("chmod +x /usr/local/bin/*.py", shell=True)

    if os.path.exists("config.env"):
        shutil.copy("config.env", "/etc/soc/config.env")
    elif os.path.exists("config_templates/config.env.example"):
        shutil.copy("config_templates/config.env.example", "/etc/soc/config.env")
        print("\033[0;36mINFO: config.env not found. Example file copied. Please edit /etc/soc/config.env after installation.\033[0m")

    print("[5/6] Starting database...")
    run_cmd(["python3", "/usr/local/bin/soc-db-init.py"])

    print("[6/6] Installing background services...")
    if os.path.exists("config_templates/soc-bot-listener.service"):
        shutil.copy("config_templates/soc-bot-listener.service", "/etc/systemd/system/soc-bot-listener.service")
        run_cmd(["systemctl", "daemon-reload"])
        run_cmd(["systemctl", "enable", "soc-bot-listener"])
        run_cmd(["systemctl", "restart", "soc-bot-listener"])
    else:
        print("\033[0;36mWARNING: Service file (soc-bot-listener.service) not found, manual installation may be required.\033[0m")

    print("\n\033[0;32m✔ Installation completed!\033[0m")
    print("To monitor logs: \033[0;36mjournalctl -f -u soc-bot-listener\033[0m")
    print("\nTo ensure the system works, make sure to enter API Key and Token values in '/etc/soc/config.env'")

if __name__ == "__main__":
    main()
