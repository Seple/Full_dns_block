import requests
import os
import shutil
import concurrent.futures
import datetime

# Linki do pobrania list
urls = [
    # 1Hosts - Różne poziomy filtracji
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Pro/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/mini/adblock.txt",
    # Filtry AdGuard
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    # Hagezi - Różne poziomy filtracji
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    # Kolejne filtry AdGuard
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
]

# Lista wykluczeń
exclude_list = {
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
    "mycafe.games",
    "tinyco.com",
    "shephertz.com",
    "hihonorcloud.com",
    "matchmasters.io",
    "candivore.com",
    "salusconnect.io",
    "v-speed.eu",
    "schwarz",
    "weathercn.com",
    "googletagmanager.com",
    "adservice.google",
    "googleadservices.com",
}

# Pliki wynikowe
output_file = "Full_DNS_Block.txt"
backup_file = "Backup_Full_DNS_Block.txt"
temp_file = output_file + ".tmp"

def generate_header():
    """Tworzy komentarz z datą i liczbą reguł"""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return f"[Adblock Plus] \n! Title: Full_DNS_Block \n! Description: Linked lists to reduce size \n! Homepage: https://github.com/Seple/Full_DNS_Block \n! Last modified: {timestamp} \n! Number of entries: {len(all_rules)} \n\n"

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

all_rules = set()
total_downloaded = 0

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    results = executor.map(fetch_list, urls)
    
    for lines in results:
        total_downloaded += len(lines)
        for line in lines:
            line = line.strip()
            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                parts = line.split()
                if len(parts) == 2:
                    rule = f"||{parts[1]}^"
                else:
                    continue
            elif line.startswith("||") and line.endswith("^"):
                rule = line
            else:
                continue
            
            domain_only = rule[2:-1]
            if not any(domain_only.endswith(f".{excluded}") or domain_only == excluded for excluded in exclude_list):
                all_rules.add(rule)

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
    print(f"📊 Podsumowanie: Pobranie: {total_downloaded} reguł, Usunięte (duplikaty i subdomeny): {removed_rules} reguł, Pozostałe unikalne po usunięciu duplikatów i subdomen: {len(all_rules)} reguł")
except Exception as e:
    print(f"❌ Błąd zapisu pliku: {e}")
