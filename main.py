import requests

# Linki do pobrania list - możesz je dowolnie edytować
urls = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_38.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_51.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Pro/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Xtra/adblock.txt",
    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/mini/adblock.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_14.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_41.txt",
]

# Lista wykluczeń (można łatwo edytować) - możesz dodać domeny z gwiazdkami, jeśli chcesz uwzględnić subdomeny
exclude_list = [
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
    "googletagmanager.com",
    "adservice.google",
    "googleadservices.com",
    "mycafe.games",
    "tinyco.com",
    "shephertz.com",
    "hihonorcloud.com",
    "matchmasters.io",
    "candivore.com",
    "salusconnect.io",
    "v-speed.eu",
    ".schwarz",
    "weathercn.com",
    # Możesz dodać też wpisy z gwiazdką dla subdomen:
    "*.hihonorcloud.com",
    "*.salusconnect.io"
]

# Funkcja do rozpoznania, czy reguła należy do wykluczeń, uwzględniając subdomeny
def is_excluded(rule):
    for exclude in exclude_list:
        if '*' in exclude:  # Domena zawierająca gwiazdkę
            base_domain = exclude.lstrip("*")  # Usuwamy gwiazdkę
            if base_domain in rule:  # Jeżeli linia zawiera subdomenę, wykluczamy
                return True
        else:  # Sprawdzamy pełne domeny
            if exclude in rule:
                return True
    return False

# Plik wynikowy
output_file = "FULL_lista.txt"

# Zbiór do przechowywania reguł
all_rules = set()

# Pobieranie i scalanie list
for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Sprawdzanie, czy odpowiedź jest poprawna
        rules = response.text.splitlines()  # Dzielimy tekst na linie

        # Usuwamy linie zaczynające się od "!" oraz "#" (komentarze) oraz puste linie
        rules = [line for line in rules if line.startswith("||")]

        # Usuwamy reguły znajdujące się na liście wykluczeń
        rules = [line for line in rules if not is_excluded(line)]

        # Dodajemy reguły do zbioru (eliminując duplikaty)
        all_rules.update(rules)
        print(f"✅ Pobrano: {url}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Błąd pobierania {url}: {e}")

# Zapis do pliku, sortowanie i eliminowanie podwójnych duplikatów
with open(output_file, "w", encoding="utf-8") as f:
    # Posortowanie i zapisanie unikalnych reguł
    f.write("\n".join(sorted(all_rules)))  # Zapisujemy posortowane reguły

print(f"\n✅ Gotowe! Zoptymalizowana lista zapisana w {output_file}")
