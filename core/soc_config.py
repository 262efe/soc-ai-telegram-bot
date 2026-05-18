import os

CLOUDFLARE_PREFIXES = [
    "173.245.", "103.21.", "103.22.", "103.31.",
    "141.101.", "108.162.", "190.93.", "188.114.",
    "197.234.", "198.41.", "162.158.", "162.159.",
    "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "104.22.", "104.23.", "104.24.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    "172.68.", "172.69.", "172.70.", "172.71.",
    "131.0.72.",
]

def load_soc_config():
    """
    Reads /etc/soc/config.env and returns settings as a dictionary.
    """
    config_path = "/etc/soc/config.env"
    # If file doesn't exist (dev env), look in local directory
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
