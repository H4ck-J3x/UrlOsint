import requests
import os
import socket
import shodan
import json
from typing import List, Dict, Any, Optional, Tuple
import sys


os.system('clear')

# Chargement de la configuration API
def load_api_config(filename: str = "api.json") -> Dict[str, Any]:
    """Charge la configuration API depuis le fichier JSON."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Erreur: Le fichier '{filename}' n'a pas été trouvé.")
        print("Créez un fichier 'api.json' avec la configuration appropriée.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Erreur lors de la lecture du JSON: {e}")
        sys.exit(1)

# Chargement des endpoints depuis le fichier JSON
def load_endpoints(filename: str = "endpoints.json") -> List[Tuple[str, str, str]]:
    """Charge les endpoints depuis le fichier JSON et les convertit en liste de tuples."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return [
                (endpoint["name"], endpoint["path"], endpoint["description"])
                for endpoint in data["endpoints"]
            ]
    except FileNotFoundError:
        print(f"❌ Erreur: Le fichier '{filename}' n'a pas été trouvé.")
        print("Créez un fichier 'endpoints.json' avec la structure appropriée.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Erreur lors de la lecture du JSON: {e}")
        sys.exit(1)
    except KeyError as e:
        print(f"❌ Erreur de structure JSON: clé manquante {e}")
        sys.exit(1)

# Chargement de la configuration
API_CONFIG = load_api_config()
files_to_check = load_endpoints()

# Configuration HTTP depuis api.json
MAX_LINES = API_CONFIG["http_settings"]["max_lines"]
MAX_LINE_LENGTH = API_CONFIG["http_settings"]["max_line_length"]
TIMEOUT = API_CONFIG["http_settings"]["timeout"]
HEADERS = API_CONFIG["http_settings"]["headers"]

# Palette de couleurs RGB pour le dégradé cyclique depuis api.json
GRADIENT_COLORS = [tuple(color) for color in API_CONFIG["display_settings"]["gradient_colors"]]

# Couleurs Shodan depuis api.json
SHODAN_COLORS = {
    key: tuple(value) 
    for key, value in API_CONFIG["display_settings"]["shodan_colors"].items()
}

def color_text(text: str, rgb: Tuple[int, int, int]) -> str:
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m{text}\033[0m"

def make_ansi_hyperlink(text: str, url: str) -> str:
    ESC = "\x1b"
    return f"{ESC}]8;;{url}{ESC}\\{text}{ESC}]8;;{ESC}\\"

def is_probably_text(content_type: str) -> bool:
    if not content_type:
        return False
    ct = content_type.split(";")[0].strip().lower()
    return ct.startswith("text/") or ct in (
        "application/json",
        "application/javascript",
        "application/xml",
        "application/xhtml+xml",
        "application/rss+xml"
    )

def is_likely_html_fallback(text: str) -> bool:
    text_lower = text.strip().lower()
    return (
        "<!doctype html" in text_lower or
        text_lower.startswith("<html") or
        "<html" in text_lower[:200]
    )

def ensure_scheme(domain_raw: str) -> str:
    domain_raw = domain_raw.strip()
    if domain_raw.startswith("http://") or domain_raw.startswith("https://"):
        return domain_raw.rstrip("/")
    return "https://" + domain_raw.rstrip("/")

def truncate_line(line: str, max_length: int) -> str:
    return line if len(line) <= max_length else line[:max_length - 1] + "…"

def print_first_lines(text: str, max_lines: int = MAX_LINES):
    lines = text.splitlines()
    if not lines:
        print("  (aucune ligne affichable)")
        return
    to_show = lines[:max_lines]
    print("        ")
    for idx, line in enumerate(to_show, start=1):
        print(f"  {idx:>2}: {truncate_line(line, MAX_LINE_LENGTH)}")
    if len(lines) > max_lines:
        print(f"  ... (affiché {max_lines} premières lignes)")

def try_fetch(url: str):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        return r if r.status_code == 200 else None
    except requests.RequestException:
        return None


def clean_domain(domain: str) -> str:
    """Normalise l'entrée et retire schéma / chemin."""
    d = domain.strip()
    if d.startswith("http://"):
        d = d[len("http://"):]
    elif d.startswith("https://"):
        d = d[len("https://"):]
    return d.split("/")[0].lower()

def resolve_ips(domain: str) -> List[str]:
    """Résout le nom de domaine en adresses IP (IPv4)."""
    domain = clean_domain(domain)
    ips = set()
    try:
        for res in socket.getaddrinfo(domain, None):
            ip = res[4][0]
            if "." in ip:
                ips.add(ip)
    except Exception:
        pass
    return sorted(ips)

def lookup_shodan_for_domain(domain: str, api_key: Optional[str] = None, search_limit: Optional[int] = None) -> Dict[str, Any]:
    domain = clean_domain(domain)
    
    # Utiliser les valeurs de api.json si non fourni
    if api_key is None:
        api_key = API_CONFIG["shodan"]["api_key"]
    if search_limit is None:
        search_limit = API_CONFIG["shodan"]["search_limit"]
    
    # priorité: param > config > env
    api_key = api_key or os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise ValueError("Clé Shodan non fournie. Passe api_key, définis dans api.json ou dans SHODAN_API_KEY.")

    client = shodan.Shodan(api_key)

    result: Dict[str, Any] = {
        "domain": domain,
        "ips_from_dns": resolve_ips(domain),
        "filtered_hosts": {},
        "cves": set(),
        "errors": []
    }

    # 1) Recherche hostname:"domain"
    try:
        query = f'hostname:"{domain}"'
        search_res = client.search(query, limit=search_limit)
        matches = search_res.get("matches", [])
    except shodan.APIError as e:
        result["errors"].append(f"Shodan search error: {e}")
        matches = []
    except Exception as e:
        result["errors"].append(f"Shodan search unexpected error: {e}")
        matches = []

    # 2) Filtrer les matches
    domain_token = domain.replace('.', ' ')
    for m in matches:
        hostnames = m.get("hostnames") or []
        ip = m.get("ip_str")
        keep = False
        kept_hostname = None
        for hn in hostnames:
            if domain in hn or hn.endswith(domain) or domain.split('.')[0] in hn:
                keep = True
                kept_hostname = hn
                break
        if not keep:
            continue

        key = kept_hostname or ip or "(unknown)"
        entry = result["filtered_hosts"].setdefault(key, {"ips": set(), "ports": set(), "vulns": set()})

        if ip:
            entry["ips"].add(ip)
        if m.get("port"):
            entry["ports"].add(m.get("port"))
        for c in m.get("vulns") or []:
            if c and isinstance(c, str) and c.upper().startswith("CVE-"):
                entry["vulns"].add(c.upper())
                result["cves"].add(c.upper())

    # 3) host(ip) pour récupérer infos supplémentaires
    ips_to_check = set()
    for h in result["filtered_hosts"].values():
        ips_to_check.update(h["ips"])
    ips_to_check.update(result["ips_from_dns"])

    for ip in sorted(ips_to_check):
        try:
            host_info = client.host(ip)
            ports = host_info.get("ports", [])
            for hkey, hval in result["filtered_hosts"].items():
                if ip in hval["ips"]:
                    for p in ports:
                        hval["ports"].add(p)
                    for c in host_info.get("vulns") or []:
                        if isinstance(c, str) and c.upper().startswith("CVE-"):
                            hval["vulns"].add(c.upper())
                            result["cves"].add(c.upper())

        except shodan.APIError as e:
            result["errors"].append(f"Shodan host error for {ip}: {e}")
        except Exception as e:
            result["errors"].append(f"Shodan host unexpected error for {ip}: {e}")

    for k, v in result["filtered_hosts"].items():
        v["ips"] = sorted(v["ips"])
        v["ports"] = sorted(v["ports"])
        v["vulns"] = sorted(v["vulns"])

    result["cves"] = sorted(result["cves"])

    return result


def pretty_print_shodan_result(
    res: Dict[str, Any],
    sample_ips_per_host: Optional[int] = None,
    link_style: Optional[str] = None,
    url_template: Optional[str] = None
):
    """Affiche le résultat Shodan avec coloration des titres."""
    
    # Utiliser les valeurs de api.json si non fourni
    if sample_ips_per_host is None:
        sample_ips_per_host = API_CONFIG["shodan"]["sample_ips_per_host"]
    if link_style is None:
        link_style = API_CONFIG["shodan"]["link_style"]
    if url_template is None:
        url_template = API_CONFIG["shodan"]["url_template"]

    def make_link(cve: str) -> str:
        url = url_template.format(cve=cve)
        if link_style == "terminal":
            start = f"\x1b]8;;{url}\x1b\\"
            end = "\x1b]8;;\x1b\\"
            return f"{start}{cve}{end}"
        elif link_style == "markdown":
            return f"[{cve}]({url})"
        elif link_style == "html":
            return f'<a href="{url}">{cve}</a>'
        else:
            return f"{cve} ({url})"

    # Couleurs depuis api.json
    BLUE_TITLE = SHODAN_COLORS["blue_title"]
    HOST_IPS_COLOR = SHODAN_COLORS["host_ips_color"]
    RED_EXPLOITS = SHODAN_COLORS["red_exploits"]

    is_tty = sys.stdout.isatty()
    def maybe_color(text: str, rgb: Tuple[int,int,int]) -> str:
        return color_text(text, rgb) if is_tty else text

    domain = res.get("domain")

    # IP(s) résolue(s)
    if res.get("ips_from_dns"):
        title = maybe_color("🖧 IP résolue :", BLUE_TITLE)
        ips_line = ", ".join(res["ips_from_dns"])
        print(f"{title} {ips_line}")
        print(" ")
    else:
        title = maybe_color("🖧 IP résolue :", BLUE_TITLE)
        print(f"{title} (aucune)\n")

    # Hosts filtrés
    if res.get("filtered_hosts"):
        for host, info in res["filtered_hosts"].items():
            host_label = maybe_color("- Host:", HOST_IPS_COLOR)
            print(f"{host_label} {host}")
            if info.get("ips"):
                ips_label = maybe_color("- IPs:", HOST_IPS_COLOR)
                print(f"{ips_label} {', '.join(info['ips'][:sample_ips_per_host])}")
                print(" ")
    else:
        print("\nHosts filtrés : (aucun host trouvé contenant le nom du domaine)")

    # Exploits / CVE
    cves = res.get("cves") or []
    exploits_title = maybe_color("\n👾 Exploits :", RED_EXPLOITS)
    if cves:
        if link_style == "terminal" and not sys.stdout.isatty():
            cve_display = ", ".join(f"{c} ({url_template.format(cve=c)})" for c in cves)
        else:
            cve_display = ", ".join(make_link(c) for c in cves)
        print(f"{exploits_title} {cve_display}")
    else:
        print(f"{exploits_title} (aucun CVE listé)")

    # Erreurs éventuelles
    if res.get("errors"):
        print("\nErreurs / infos :")
        for err in res["errors"]:
            print("  -", err)

    print("\n----------------------------------------------------\n")


def print_ascii_title():
    ascii_art = """
        ▄  ▄▌▄▄▄  ▄▄▌           ▄▄       ▐ ▄ ▄▄▄▄▄
        █ ██▌▀▄ █ ██      ▄█▀▄ ▐█ ▀  ██  █▌▐█ ██  
        █▌▐█▌▐▀▀▄ ██     ▐█▌ ▐▌▄▀▀▀█▄▐█  █▐▐▌ ▐█  
        ▐█▄█▌▐█ █▌▐█▌ ▄  ▐█▌ ▐▌ █▄ ▐█▐█▌██▐█▌ ▐█▌ 
         ▀▀▀  ▀  ▀ ▀▀▀    ▀█▄▀  ▀▀▀▀ ▀▀▀▀▀ █  ▀▀▀ 
    \n"""
    blue = SHODAN_COLORS["blue_title"]
    print(color_text(ascii_art, blue))

def main():
    print_ascii_title()
    domain_input = input("  Entrer le nom de domaine à investiguer (ex: domain.com) :\n\n  > ").strip()
    print()
    base = ensure_scheme(domain_input)

    try:
        report = lookup_shodan_for_domain(base)
        pretty_print_shodan_result(report)
    except Exception as e:
        print("Erreur:", e)

    for i, (name, path, _) in enumerate(files_to_check):
        url = base + path
        r = try_fetch(url)
        if not r:
            continue

        # Lecture & validation
        content = ""
        try:
            content = r.text
        except Exception:
            try:
                content = r.content.decode(r.encoding or "utf-8", errors="replace")
            except Exception:
                continue

        if is_likely_html_fallback(content):
            continue

        # Dégradé cyclique
        color = GRADIENT_COLORS[i % len(GRADIENT_COLORS)]

        # Lien cliquable
        label = make_ansi_hyperlink(f"{name}:", url)
        colored_label = color_text(label, color)
        print(f"\n{colored_label} ({url})")

        print_first_lines(content, MAX_LINES)
        print(" ")
        print("-" * 80)

if __name__ == "__main__":
    main()