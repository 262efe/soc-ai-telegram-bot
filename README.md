# SOC AI Telegram Bot - Automated Monitoring & Alert System
```text
  ____   ___   ____       _    ___   _____    _                                
 / ___| / _ \ / ___|     / \  |_ _| |_   _|__| | ___  __ _ _ __ __ _ _ __ ___  
 \___ \| | | | |   _____/ _ \  | |    | |/ _ \ |/ _ \/ _` | '__/ _` | '_ ` _ \ 
  ___) | |_| | |__|_____/ ___ \| |    | |  __/ |  __/ (_| | | | (_| | | | | | |
 |____/ \___/ \____|   /_/   \_\___|  |_|\___|_|\___|\__, |_|  \__,_|_| |_| |_|
                                                     |___/                     
```


This repository contains a comprehensive, automated Security Operations Center (SOC) framework designed to monitor server activity, detect malicious attempts in real-time, instantly ban attackers via Nginx and system firewalls, and alert administrators via Telegram.

## Features

- **Real-Time Monitoring:** Continuously monitors server resources, SSH logins, sudo activities, Nginx access/error logs, and site availability.
- **Automated Threat Response:** Detects SQL Injection, XSS, Directory Scanning, Code Injection, and SSH Brute-Force attacks. Unwanted IPs are automatically banned via Nginx deny rules.
- **Telegram Bot Integration:** Allows you to control your SOC from your Telegram app. Receive real-time alerts and run commands to ban/unban IPs, view logs, get server status, and analyze threats.
- **Groq API Integration:** Analyzes raw server logs and attack patterns autonomously using AI (LLM integration) to provide actionable insights.
- **Auto-Ban / Unban Mechanism:** Dynamically maintains ban lists and unbans IPs based on configurable expiration rules.
- **Whitelist & Cloudflare Support:** Built-in safeguards to prevent banning Cloudflare IP ranges or explicitly whitelisted IP addresses.

## Prerequisites

- Linux Server (Ubuntu/Debian recommended)
- `python3` and `pip` (for Python modules)
- `nginx`
- `ufw` (for firewall management)
- `sqlite3`
- A Telegram Bot (created via BotFather)
- A Groq API Key (for the LLM-powered log analyzer)

## Installation Guide

1. **Clone the Repository**
```bash
   git clone https://github.com/262efe/soc-ai-telegram-bot.git
   cd soc-ai-telegram-bot
```

2. **Setup Configuration**
   Copy the example environment configuration and fill in your details:
```bash
   cp config.env.example config.env
   nano config.env
```
   *Note: Add your Telegram Bot Token, Telegram Chat ID, and Groq API Key.*

3. **Run the Automated Installer**
   Run the automated script to install project requirements, setup directories, and start background services:
```bash
   chmod +x install.sh
   sudo ./install.sh
```

## Key Files & Structure

- `soc-log-analyzer.sh`: Uses AI (Groq API) to read Nginx and kernel logs and generates a human-readable threat intelligence report.
- `soc-rule-engine.py`: Defines the attack criteria and automated responses.
- `soc_config.py`: Centralized configuration utility for all SOC components.
- `soc-auto-ban.py / soc-auto-unban.py`: Logic to securely block or release IP addresses.
- `soc-bot-listener.py`: Telegram Bot logic. Listens for your commands like `/ban`, `/unban`, `/durum`, `/tehdit`, etc.
- `soc-notifier.py`: Sends detected threats to Telegram and manages approval/rejection buttons.
- `soc-daily-report.py`: Aggregates the daily threat data and sends a summary to your Telegram chat.
- `soc-db-init.py`: Creates and initializes the database tables.
- `soc-db-save.py`: Masks and saves analysis results and threats to the database.
- `nginx-ban-ip.py / nginx-unban-ip.py`: Hardened Python scripts for atomic Nginx configuration updates and IP validation.
- `nginx-ban-ip.sh / nginx-unban-ip.sh`: Wrapper Bash scripts for manual or automated ban/unban operations.
- `block-sensitives.conf & cloudflare-real-ip.conf`: Production-ready Nginx configuration snippets to block access to sensitive files (`.env`, `.git`, etc.) and resolve real IPs behind Cloudflare.

## Telegram Bot Commands

- `/log <hours>` - Displays the log summary (Nginx, SSH, UFW) of the last X hours (e.g., `/log 2`)
- `/durum` - Shows real-time system CPU, RAM, disk usage, and background service status
- `/banlist` - Lists the currently banned IPs and recent ban logs
- `/ban <ip> <duration> <reason>` - Bans the given IP temporarily or permanently (`1s`, `1g`, `7g`, `kalici`)
- `/unban <ip>` - Removes an IP ban from the Nginx firewall
- `/tehdit` - Lists today's detected and blocked threat history
- `/analiz` - Instantly triggers a manual deep analysis of server logs using the Groq LLM API
- `/istatistik` - Presents security statistics for the last 7 days
- `/yardim` - Displays the command help menu

## Customization

- Adjust rule severities and ban durations in `soc-rule-engine.py` to tune the system for your environment.

## Privacy & Security

IP addresses, email addresses, passwords and Bearer tokens are automatically masked before being sent to the Groq API.

> ⚠️ Each user must create their own Groq API key.
> Never share or transfer your API keys to others.

## How Is This Different From Fail2ban?

Fail2ban operates on static rules and only recognizes known attack patterns. This system goes further by:

- **AI-powered log analysis** to detect unknown and emerging threats
- **Real-time Telegram notifications** so you're always in the loop
- **Approval mechanism** to prevent false positives — it asks before banning
- **Daily summary reports** giving you a full picture of your security posture
- Can be used alongside Fail2ban — they complement, not replace each other

## Frequently Asked Questions (FAQ)

**What if my bot token gets stolen?**
The bot only responds to the chat ID defined in `config.env`.
Even if someone obtains the token, they cannot execute any commands.

**What happens if the Groq API goes down?**
The rule engine operates independently of AI. Critical threats are automatically banned even without AI analysis.

**What if I accidentally ban my own IP?**
The whitelist mechanism automatically protects your server's IP.
You can also remove any ban manually using the `/unban <ip>` command.

**Is Cloudflare required?**
No, the system works without Cloudflare. `cloudflare-real-ip.conf` is entirely optional.

**Is Groq free?**
Yes, the free tier allows hundreds of analyses per day.
Each user can create their own free API key at [console.groq.com](https://console.groq.com).

**Is the database secure? Does it contain sensitive information?**
The database is stored as an unencrypted SQLite file, but it contains no raw log data. Only masked threat analyses, ban history, and statistics are stored. All personal data including IP addresses is masked before being written to the database. File permissions should be set to `root:root 600` so that only the root user can access it.



## Contact

Feel free to reach out for any issues, suggestions, or contributions:

- 🌐 Website: [efealtintas.com](https://efealtintas.com)
- 📧 Email: [hi@efealtintas.com](mailto:hi@efealtintas.com)

## ⚠️ Disclaimer

This software is developed to **assist** with server security; it does not guarantee complete protection. The **user assumes full responsibility** for any damages arising from the use of this software, including but not limited to data loss, security breaches, or system outages.

- Test in a staging environment before deploying to production
- Take regular backups
- This tool is not a substitute for professional security consulting

## License

MIT License.



# SOC AI Telegram Bot - Otomatik İzleme ve Uyarı Sistemi
```text
  ____   ___   ____       _    ___   _____    _                                
 / ___| / _ \ / ___|     / \  |_ _| |_   _|__| | ___  __ _ _ __ __ _ _ __ ___  
 \___ \| | | | |   _____/ _ \  | |    | |/ _ \ |/ _ \/ _` | '__/ _` | '_ ` _ \ 
  ___) | |_| | |__|_____/ ___ \| |    | |  __/ |  __/ (_| | | | (_| | | | | | |
 |____/ \___/ \____|   /_/   \_\___|  |_|\___|_|\___|\__, |_|  \__,_|_| |_| |_|
                                                     |___/                     
```


Bu depo, sunucu etkinliklerini izlemek, kötü niyetli girişimleri gerçek zamanlı olarak tespit etmek, saldırganları Nginx ve sistem güvenlik duvarları aracılığıyla anında engellemek ve yöneticileri Telegram üzerinden uyarmak için tasarlanmış kapsamlı, otomatik bir Güvenlik Operasyon Merkezi (SOC) yapısı içerir.

## Özellikler

- **Gerçek Zamanlı İzleme:** Sunucu kaynaklarını, SSH girişlerini, sudo etkinliklerini, Nginx erişim/hata loglarını ve site erişilebilirliğini sürekli olarak izler.
- **Otomatik Tehdit Yanıtı:** SQL Injection, XSS, Dizin Tarama, Kod Enjeksiyonu ve SSH Brute-Force saldırılarını tespit eder. İstenmeyen IP'ler, Nginx deny kuralları aracılığıyla otomatik olarak engellenir (banlanır).
- **Telegram Bot Entegrasyonu:** SOC sisteminizi Telegram uygulamanızdan yönetmenizi sağlar. Gerçek zamanlı uyarılar alın ve IP banlama/ban kaldırma, logları görüntüleme, sunucu durumunu öğrenme ve tehditleri analiz etme komutlarını çalıştırın.
- **Groq API Entegrasyonu:** Tehdit raporları sağlamak için yapay zeka (LLM entegrasyonu) kullanarak ham sunucu loglarını ve saldırı modellerini otonom olarak analiz eder.
- **Otomatik Ban / Ban Kaldırma Mekanizması:** Ban listelerini dinamik olarak yönetir ve yapılandırılabilir süre kurallarına göre IP'lerin yasaklarını otomatik olarak kaldırır.
- **Beyaz Liste (Whitelist) & Cloudflare Desteği:** Cloudflare IP aralıklarının veya açıkça beyaz listeye alınmış IP adreslerinin yanlışlıkla engellenmesini önlemek için yerleşik korumalar.

## Gereksinimler

- Linux Sunucu (Ubuntu/Debian önerilir)
- `python3` ve `pip` (Python modülleri için)
- `nginx`
- `ufw` (güvenlik duvarı yönetimi için)
- `sqlite3`
- Bir Telegram Botu (BotFather üzerinden oluşturulmuş)
- Bir Groq API Anahtarı (Yapay zeka analizörü için)

## Kurulum Rehberi

1. **Projeyi Klonlayın**
```bash
   git clone https://github.com/262efe/soc-ai-telegram-bot.git
   cd soc-ai-telegram-bot
```

2. **Konfigürasyonu Ayarlayın**
   Örnek çevre değişkenleri konfigürasyonunu kopyalayın ve kendi bilgilerinizi doldurun:
```bash
   cp config.env.example config.env
   nano config.env
```
   *Not: Telegram Bot Token'ınızı, Telegram Chat ID'nizi ve Groq API Key'inizi ekleyin.*

3. **Otomatik Kurulum Scriptini Çalıştırın**
   Projenin gereksinimlerini kurmak, dizinlerini ayarlamak ve arka plan servislerini başlatmak için otomatik scripti çalıştırın:
```bash
   chmod +x install.sh
   sudo ./install.sh
```

## Önemli Dosyalar ve Yapı

- `soc-log-analyzer.sh`: Nginx ve kernel loglarını okumak için yapay zeka (Groq API) kullanır ve okunabilir bir tehdit raporu oluşturur.
- `soc-rule-engine.py`: Saldırı kriterlerini ve bunlara verilecek otomatik tepkileri tanımlar.
- `soc_config.py`: Tüm SOC bileşenleri için merkezi yapılandırma aracıdır.
- `soc-auto-ban.py / soc-auto-unban.py`: IP adreslerini güvenli bir şekilde engelleme veya serbest bırakma mekanizmasıdır.
- `soc-bot-listener.py`: Telegram Bot altyapısıdır. `/ban`, `/unban`, `/durum`, `/tehdit` vb. komutlarınızı çalıştırır.
- `soc-notifier.py`: Tespit edilen tehditleri Telegram'a gönderir, onay/red butonlarını yönetir.
- `soc-daily-report.py`: Günlük tehdit verilerini toparlar ve Telegram hesabınıza bir özet gönderir.
- `soc-db-init.py`: Veritabanı tablolarını oluşturur ve başlatır.
- `soc-db-save.py`: Analiz sonuçlarını ve tehditleri maskeleyerek veritabanına kaydeder.
- `nginx-ban-ip.py / nginx-unban-ip.py`: Atomik Nginx konfigürasyon güncellemeleri ve IP doğrulaması yapan sertleştirilmiş Python betikleridir.
- `nginx-ban-ip.sh / nginx-unban-ip.sh`: Manuel veya otomatik ban/unban işlemleri için kullanılan sarmalayıcı Bash betikleridir.
- `block-sensitives.conf & cloudflare-real-ip.conf`: Kritik dosyalara (`.env`, `.git` vb.) doğrudan erişimi kesmek ve Cloudflare arkasından gelen gerçek IP'leri çözümlemek için üretime hazır Nginx konfigürasyon parçacıklarıdır.

## Telegram Bot Komutları

Bot üzerinden kullanabileceğiniz komutlar şunlardır:

- `/log <saat>` - Son X saatin Nginx, SSH ve UFW log özetini gösterir (Örn: `/log 2`)
- `/durum` - Sistem CPU, RAM, disk kullanımı ve arka plan servislerinin güncel durumunu gösterir
- `/banlist` - Aktif engellenmiş (banlı) IP listesini ve son ban kayıtlarını listeler
- `/ban <ip> <süre> <sebep>` - Belirtilen IP adresini kalıcı veya geçici (`1s`, `1g`, `7g`, `kalici`) olarak banlar (Örn: `/ban 1.2.3.4 7g brute_force`)
- `/unban <ip>` - Nginx güvenlik duvarındaki bir IP yasaklamasını kaldırır
- `/tehdit` - Bugün tespit edilen ve engellenen tehditlerin dökümünü listeler
- `/analiz` - Groq LLM API ile sunucu loglarının manuel derin analizini anında başlatır
- `/istatistik` - Son 7 günün güvenlik istatistiklerini (Kritik, Yüksek, Orta seviyeli tehditler vb.) sunar
- `/yardim` - Komut yardım menüsünü görüntüler

## Özelleştirme

- Ortamınızın ihtiyaçlarına göre ayarlamalar yapmak için `soc-rule-engine.py` içindeki kuralları ve ban sürelerini değiştirebilirsiniz.

## Gizlilik & Güvenlik

IP adresleri, e-posta adresleri, şifreler ve Bearer token'lar Groq API'ye gönderilmeden önce otomatik olarak maskelenir.

> ⚠️ Her kullanıcı kendi Groq API anahtarını oluşturmalıdır.
> API anahtarlarını paylaşmayın veya başkalarına devretmeyin.

## Fail2ban'dan Farkı Nedir?

Fail2ban kural tabanlı çalışır ve sadece bilinen saldırı kalıplarını tanır. Bu sistem ise:

- **Yapay zeka ile log analizi** yaparak bilinmeyen tehditleri de tespit eder
- **Telegram üzerinden gerçek zamanlı bildirim** gönderir
- **Onay mekanizması** ile yanlış pozitifleri önler — ban atmadan önce size sorar
- **Günlük özet rapor** ile genel güvenlik durumunu sunar
- Fail2ban ile birlikte kullanılabilir, birbirinin alternatifi değildir

## Sık Sorulan Sorular (SSS)

**Bot token çalınırsa ne olur?**
Bot sadece `config.env`'de tanımlı chat ID'ye yanıt verir.
Başka biri token'ı ele geçirse bile komut çalıştıramaz.

**Groq API çökerse ne olur?**
Kural motoru AI'dan bağımsız çalışır. Kritik tehditler AI olmadan da otomatik banlanır.

**Yanlışlıkla kendi IP'mi banlarsam?**
Whitelist mekanizması var, kendi sunucu IP'niz otomatik korunur.
Manuel `/unban <ip>` komutu ile de ban kaldırılabilir.

**Cloudflare zorunlu mu?**
Hayır, Cloudflare olmadan da çalışır. `cloudflare-real-ip.conf` opsiyoneldir.

**Groq ücretsiz mi?**
Evet, free tier ile günlük yüzlerce analiz yapabilirsiniz.
Her kullanıcı [console.groq.com](https://console.groq.com) adresinden kendi ücretsiz API anahtarını oluşturabilir.

**Veritabanı güvenli mi, içinde hassas bilgi var mı?**
Veritabanı şifrelenmemiş SQLite formatında saklanır ancak içinde ham log verisi bulunmaz. Yalnızca maskelenmiş tehdit analizleri, ban geçmişi ve istatistikler tutulur. IP adresleri dahil tüm kişisel veriler veritabanına yazılmadan önce maskelenir. Dosya izinleri `root:root 600` olarak ayarlanmalı, yalnızca root kullanıcısı erişebilmelidir.



## İletişim

Herhangi bir sorun, öneri veya katkı için benimle iletişime geçebilirsiniz:

- 🌐 Website: [efealtintas.com](https://efealtintas.com)
- 📧 E-posta: [hi@efealtintas.com](mailto:hi@efealtintas.com)

## ⚠️ Sorumluluk Reddi

Bu yazılım, sunucu güvenliğinizi **desteklemek** amacıyla geliştirilmiştir; tam güvenlik garantisi vermez. Yazılımın kullanımından doğabilecek veri kayıpları, güvenlik ihlalleri veya sistem kesintileri dahil tüm zararlardan **kullanıcı sorumludur**.

- Canlı ortamda kullanmadan önce test ortamında deneyiniz
- Düzenli yedek alınız
- Bu araç, profesyonel güvenlik danışmanlığının yerini tutmaz

## Lisans

MIT License.

---
