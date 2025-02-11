import requests
import os
import shutil
import concurrent.futures
import datetime
import re

# Linki do pobrania list
urls = [
    # 1Hosts - Różne poziomy filtracji
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/mini/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Pro/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    # Hagezi - Różne poziomy filtracji
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    # OISD - Różne poziomy filtracji
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
    # Peter Lowe's Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    # Steven Black's List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    # Dan Pollock's List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    # AdGuard DNS filter
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    # AWAvenue Ads Rule
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt",
    # Malicious URL Blocklist (URLHaus)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    # uBlock filters – Badware risks
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
    # Stalkerware Indicators List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    # ShadowWhisperer's Malware List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    # Scam Blocklist by DurableNapkin
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    # NoCoin Filter List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
    # Dandelion Sprout's Anti-Malware List
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    # Phishing URL Blocklist (PhishTank and OpenPhish)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    # POL: Polish filters for Pi-hole
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt",
    # POL: CERT Polska List of malicious domains
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt",
    # WindowsSpyBlocker - Hosts spy rules
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt",
    # Dandelion Sprout's Anti Push Notifications
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt",
    # Dandelion Sprout's Game Console Adblock List)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt",
    # Perflyst and Dandelion Sprout's Smart-TV Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
    # HaGeZi's DynDNS Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
    # HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
    # Phishing Army
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
    # HaGeZi's Anti-Piracy Blocklist
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_46.txt",
    # HaGeZi's Fake DNS Blocklist
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt",
    # HaGeZi's Pop-Up Ads DNS Blocklist
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt",
    # KADhosts
    "https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt",
    # AdGuard Base filter
    "https://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt",
    # AdGuard Tracking Protection filter
    "https://filters.adtidy.org/extension/ublock/filters/3.txt",
    # EasyPrivacy
    "https://easylist.to/easylist/easyprivacy.txt",
    # EasyList
    "https://easylist.to/easylist/easylist.txt",
    # Easylist Cookie List
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
    # Fanboy's Annoyance List
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    # Fanboy's Social Blocking List
    "https://easylist.to/easylist/fanboy-social.txt",
    # HaGeZi's Badware Hoster DNS Blocklist
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/hoster.txt",
    # HaGeZi's safesearch not supported DNS Blocklist
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nosafesearch.txt",
        # HaGeZi's The World's Most Abused TLDs
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nosafesearch.txt",
        # Native Tracker
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nosafesearch.txt",
]

# Lista wykluczeń
exclude_list = {
    # Facebook
    "b-graph-fallback.facebook.com",
    "b-graph.facebook.com",
    "graph-fallback.facebook.com",
    "graph.facebook.com",
    "graph.fbpigeon.com",
    "z-m-graph.facebook.com",
    "web.facebook.com",
    "web-fallback.facebook.com",
    "connect.facebook.com",
    "connect.facebook.net",
    "mqtt-mini.facebook.com",
    # Gry i Aplikacje Android
    "mycafe.games",
    "tinyco.com",
    "shephertz.com",
    "hihonorcloud.com",
    "matchmasters.io",
    "candivore.com",
    "salusconnect.io",
    "v-speed.eu",
    "livechatinc.com",
    "cssott.com",
    "leaflets.schwarz",
    "assets.schwarz",
    "user.live.boltsvc.net",
    # Google
    "error222.com",
}

# Pliki wynikowe
output_file = "Full_DNS_Block.txt"
backup_file = "Backup_Full_DNS_Block.txt"
temp_file = output_file + ".tmp"

# Wyrażenia regularne do sprawdzania poprawności wpisów
valid_patterns = [
    r"^0\.0\.0\.0\s+(\S+)$",  # 0.0.0.0 example.com → example.com
    r"^127\.0\.0\.1\s+(\S+)$",  # 127.0.0.1 example.com → example.com
    r"^\|\|([a-zA-Z0-9.-]+)\^$",  # ||example.com^ (już w poprawnym formacie)
    r"^([a-zA-Z0-9.-]+)$"  # example.com (samotna domena)
]

def generate_header():
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f"""[Adblock Plus] 
! Title: Full_DNS_Block 
! Description: Linked lists to reduce size 
! Homepage: https://github.com/Seple/Full_DNS_Block 
! Last modified: {timestamp} 
! Number of entries: {len(all_rules)} 

"""  

def fetch_list(url, retries=3):
    for _ in range(retries):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            lines = response.text.splitlines()
            print(f"✅ Pobrano: {url} ({len(lines)} reguł)")
            return lines
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Błąd pobierania {url}: {e}")
    print(f"❌ Nie udało się pobrać: {url}")
    return []

def remove_subdomains(domains):
    sorted_domains = sorted(domains, key=lambda d: d.count('.'))  # Sortowanie wg liczby członów
    filtered_domains = set()
    
    for domain in sorted_domains:
        main_domain = domain.lstrip("||").rstrip("^")  # Usunięcie || i ^
        parts = main_domain.split('.')
        
        if not any(f"||{'.'.join(parts[i:])}^" in filtered_domains for i in range(1, len(parts))):
            filtered_domains.add(domain)
    
    return filtered_domains

all_rules = set()
total_downloaded = 0

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    results = executor.map(fetch_list, urls)
    
    for lines in results:
        total_downloaded += len(lines)
        for line in lines:
            line = line.strip()
            
            # Ignorowanie pustych linii oraz komentarzy
            if not line or line.startswith(('-', '.', '!', '#')):
                continue
            
            # Dopasowanie do jednego z wyrażeń regularnych
            matched = False
            for pattern in valid_patterns:
                match = re.match(pattern, line)
                if match:
                    domain = match.group(1)
                    rule = f"||{domain}^"
                    matched = True
                    break
            
            if not matched:
                continue  # Pominięcie wpisu, jeśli nie pasuje do żadnego wzorca
            
            # Sprawdzenie, czy domena nie znajduje się na liście wykluczeń
            domain_only = rule[2:-1]
            if not any(domain_only.endswith(f".{excluded}") or domain_only == excluded for excluded in exclude_list):
                all_rules.add(rule)

# Usuwanie zbędnych subdomen
all_rules = remove_subdomains(all_rules)

removed_rules = total_downloaded - len(all_rules)

# Tworzenie kopii zapasowej
if os.path.exists(output_file):
    shutil.copy(output_file, backup_file)
    print(f"🔄 Utworzono kopię zapasową: {backup_file}")

# Zapis listy z nagłówkiem
try:
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(generate_header())
        for rule in sorted(all_rules):
            f.write(rule + "\n")
    os.replace(temp_file, output_file)
    print(f"✅ Nowa lista zapisana w {output_file}")
    print(f"📊 Podsumowanie: Pobranie: {total_downloaded} reguł, Usunięte (duplikaty i subdomeny): {removed_rules} reguł, Pozostałe unikalne: {len(all_rules)} reguł")
except Exception as e:
    print(f"❌ Błąd zapisu pliku: {e}")
