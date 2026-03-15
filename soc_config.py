import os

def load_soc_config():
    """
    TR: /etc/soc/config.env dosyasını okur ve ayarları sözlük olarak döndürür.
    EN: Reads /etc/soc/config.env and returns settings as a dictionary.
    """
    config_path = "/etc/soc/config.env"
    # TR: Eğer dosya yoksa (geliştirme ortamı), yerel dizine bak
    # EN: If file doesn't exist (dev env), look in local directory
    if not os.path.exists(config_path):
        config_path = "config.env"
    
    config = {
        "DB_PATH": "/var/lib/soc/soc_logs.db", # Default
        "SERVER_IP": ""
    }
    
    if os.path.exists(config_path):
        with open(config_path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip().strip('"')
                    
    return config
