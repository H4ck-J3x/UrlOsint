"""
Utilitaires pour l'affichage coloré et formaté
"""
import sys
from typing import Tuple, Dict, Any, Optional


class DisplayUtils:
    """Utilitaires pour l'affichage dans le terminal"""
    
    @staticmethod
    def color_text(text: str, rgb: Tuple[int, int, int]) -> str:
        """Applique une couleur RGB à un texte."""
        r, g, b = rgb
        return f"\033[38;2;{r};{g};{b}m{text}\033[0m"
    
    @staticmethod
    def make_ansi_hyperlink(text: str, url: str) -> str:
        """Crée un lien hypertexte ANSI."""
        ESC = "\x1b"
        return f"{ESC}]8;;{url}{ESC}\\{text}{ESC}]8;;{ESC}\\"
    
    @staticmethod
    def truncate_line(line: str, max_length: int) -> str:
        """Tronque une ligne si elle est trop longue."""
        return line if len(line) <= max_length else line[:max_length - 1] + "…"
    
    @staticmethod
    def print_first_lines(text: str, max_lines: int = 10, max_line_length: int = 120):
        """Affiche les premières lignes d'un texte."""
        lines = text.splitlines()
        if not lines:
            print("  (aucune ligne affichable)")
            return
        
        to_show = lines[:max_lines]
        print("        ")
        for idx, line in enumerate(to_show, start=1):
            print(f"  {idx:>2}: {DisplayUtils.truncate_line(line, max_line_length)}")
        
        if len(lines) > max_lines:
            print(f"  ... (affiché {max_lines} premières lignes)")
    
    @staticmethod
    def print_ascii_title(colors: Dict[str, Tuple[int, int, int]]):
        """Affiche le titre ASCII coloré."""
        ascii_art = """
        ▄• ▄▌▄▄▄  ▄▄▌            .▄▄ · ▪   ▐ ▄ ▄▄▄▄▄
        █▪██▌▀▄ █·██•      ▪     ▐█ ▀. ██ •█▌▐█•██  
        █▌▐█▌▐▀▀▄ ██▪       ▄█▀▄ ▄▀▀▀█▄▐█·▐█▐▐▌ ▐█.▪
        ▐█▄█▌▐█•█▌▐█▌▐▌    ▐█▌.▐▌▐█▄▪▐█▐█▌██▐█▌ ▐█▌·
        ▀▀▀ .▀  ▀.▀▀▀      ▀█▄▀▪ ▀▀▀▀ ▀▀▀▀▀ █▪ ▀▀▀ 
    \n"""
        blue = colors.get("blue_title", (100, 150, 255))
        print(DisplayUtils.color_text(ascii_art, blue))


class ShodanDisplay:
    """Gestionnaire d'affichage pour les résultats Shodan"""
    
    def __init__(
        self, 
        colors: Dict[str, Tuple[int, int, int]],
        sample_ips_per_host: int = 3,
        link_style: str = "terminal",
        url_template: str = "https://nvd.nist.gov/vuln/detail/{cve}"
    ):
        self.colors = colors
        self.sample_ips_per_host = sample_ips_per_host
        self.link_style = link_style
        self.url_template = url_template
    
    def make_link(self, cve: str) -> str:
        """Crée un lien vers un CVE selon le style choisi."""
        url = self.url_template.format(cve=cve)
        
        if self.link_style == "terminal":
            start = f"\x1b]8;;{url}\x1b\\"
            end = "\x1b]8;;\x1b\\"
            return f"{start}{cve}{end}"
        elif self.link_style == "markdown":
            return f"[{cve}]({url})"
        elif self.link_style == "html":
            return f'<a href="{url}">{cve}</a>'
        else:
            return f"{cve} ({url})"
    
    def maybe_color(self, text: str, rgb: Tuple[int, int, int]) -> str:
        """Applique la couleur seulement si le terminal le supporte."""
        return DisplayUtils.color_text(text, rgb) if sys.stdout.isatty() else text
    
    def print_result(self, result: Dict[str, Any]):
        """Affiche le résultat Shodan avec formatage."""
        BLUE_TITLE = self.colors.get("blue_title", (100, 150, 255))
        HOST_IPS_COLOR = self.colors.get("host_ips_color", (150, 200, 255))
        RED_EXPLOITS = self.colors.get("red_exploits", (255, 100, 100))
        
        # IP(s) résolue(s)
        if result.get("ips_from_dns"):
            title = self.maybe_color("🖧 IP résolue :", BLUE_TITLE)
            ips_line = ", ".join(result["ips_from_dns"])
            print(f"{title} {ips_line}")
            print(" ")
        else:
            title = self.maybe_color("🖧 IP résolue :", BLUE_TITLE)
            print(f"{title} (aucune)\n")
        
        # Hosts filtrés
        if result.get("filtered_hosts"):
            for host, info in result["filtered_hosts"].items():
                host_label = self.maybe_color("- Host:", HOST_IPS_COLOR)
                print(f"{host_label} {host}")
                if info.get("ips"):
                    ips_label = self.maybe_color("- IPs:", HOST_IPS_COLOR)
                    ips_display = ', '.join(info['ips'][:self.sample_ips_per_host])
                    print(f"{ips_label} {ips_display}")
                    print(" ")
        else:
            print("\nHosts filtrés : (aucun host trouvé contenant le nom du domaine)")
        
        # Exploits / CVE
        cves = result.get("cves") or []
        exploits_title = self.maybe_color("\n💾 Exploits :", RED_EXPLOITS)
        
        if cves:
            if self.link_style == "terminal" and not sys.stdout.isatty():
                cve_display = ", ".join(f"{c} ({self.url_template.format(cve=c)})" for c in cves)
            else:
                cve_display = ", ".join(self.make_link(c) for c in cves)
            print(f"{exploits_title} {cve_display}")
        else:
            print(f"{exploits_title} (aucun CVE listé)")
        
        # Erreurs éventuelles
        if result.get("errors"):
            print("\nErreurs / infos :")
            for err in result["errors"]:
                print("  -", err)
        
        print("\n----------------------------------------------------\n")


class WaybackDisplay:
    """Gestionnaire d'affichage pour les résultats Wayback Machine"""
    
    def __init__(self, colors: Dict[str, Tuple[int, int, int]]):
        self.colors = colors
    
    def maybe_color(self, text: str, rgb: Tuple[int, int, int]) -> str:
        """Applique la couleur seulement si le terminal le supporte."""
        return DisplayUtils.color_text(text, rgb) if sys.stdout.isatty() else text
    
    def print_result(self, result: Optional[Dict[str, Any]]):
        """Affiche le résultat de la Wayback Machine."""
        BLUE_TITLE = self.colors.get("blue_title", (100, 150, 255))
        
        title = self.maybe_color("🗃️  Archives Web (Wayback Machine) :", BLUE_TITLE)
        print(f"\n{title}\n")
        
        if result is None:
            print("     - URL non archivée dans la Wayback Machine.")
        elif "error" in result:
            print(f"     - Erreur : {result['error']}")
        else:
            print(f"    - URL  : {result['url']}")
            print(f"    - Date : {result['timestamp_readable']}")
            print(f"    - Status : {result['status']}")
        
        print("\n----------------------------------------------------\n")