"""
Programme principal - Investigation de domaines
"""
import os
import sys
from typing import Optional

# Imports des modules
from config import ConfigManager
from apis.shodan_api import ShodanAPI
from apis.wayback_api import WaybackAPI
from scanner.http_scanner import HTTPScanner
from utils.display import DisplayUtils, ShodanDisplay, WaybackDisplay


class DomainInvestigator:
    """Classe principale pour l'investigation de domaines"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        
        # Initialisation des APIs (optionnelles)
        try:
            self.shodan_api = ShodanAPI(
                api_key=config.shodan_settings.get("api_key"),
                search_limit=config.shodan_settings.get("search_limit", 100)
            )
        except Exception as e:
            print(f"⚠️  Shodan non disponible: {e}")
            self.shodan_api = None
        
        self.wayback_api = WaybackAPI(
            timeout=config.http_settings.get("timeout", 20)
        )
        
        # Initialisation du scanner HTTP
        self.http_scanner = HTTPScanner(
            headers=config.http_settings["headers"],
            timeout=config.http_settings["timeout"]
        )
        
        # Initialisation des utilitaires d'affichage
        self.shodan_display = ShodanDisplay(
            colors=config.shodan_colors,
            sample_ips_per_host=config.shodan_settings.get("sample_ips_per_host", 3),
            link_style=config.shodan_settings.get("link_style", "terminal"),
            url_template=config.shodan_settings.get("url_template", "https://nvd.nist.gov/vuln/detail/{cve}")
        )
        
        self.wayback_display = WaybackDisplay(
            colors=config.shodan_colors
        )
    
    def investigate(self, domain: str, skip_shodan: bool = False, skip_wayback: bool = False):
        """
        Lance l'investigation complète d'un domaine.
        
        Args:
            domain: Le domaine à investiguer
            skip_shodan: Ne pas utiliser Shodan
            skip_wayback: Ne pas utiliser Wayback Machine
        """
        base_url = self.http_scanner.ensure_scheme(domain)
        
        # 1. Recherche Shodan
        if not skip_shodan and self.shodan_api:
            try:
                print("🔍 Recherche Shodan en cours...\n")
                shodan_result = self.shodan_api.lookup_domain(base_url)
                self.shodan_display.print_result(shodan_result)
            except Exception as e:
                print(f"❌ Erreur Shodan: {e}\n")
                print("----------------------------------------------------\n")
        elif not skip_shodan:
            print("⚠️  Scan Shodan ignoré (pas de clé API configurée)\n")
            print("----------------------------------------------------\n")
        
        # 2. Recherche Wayback Machine
        if not skip_wayback:
            try:
                wayback_result = self.wayback_api.get_archive_details(base_url)
                self.wayback_display.print_result(wayback_result)
            except Exception as e:
                print(f"❌ Erreur Wayback: {e}\n")
                print("----------------------------------------------------\n")
        
        # 3. Scan des endpoints
        print("🔍 Scan des endpoints en cours...\n")
        
        gradient_colors = self.config.gradient_colors
        max_lines = self.config.http_settings["max_lines"]
        max_line_length = self.config.http_settings["max_line_length"]
        
        found_count = [0]  # Utiliser une liste pour pouvoir modifier dans le callback
        
        def display_result(result: Dict[str, Any], index: int):
            """Callback pour afficher chaque résultat immédiatement"""
            found_count[0] += 1
            color = gradient_colors[index % len(gradient_colors)]
            
            # Lien cliquable
            label = DisplayUtils.make_ansi_hyperlink(
                f"{result['name']}:", 
                result['url']
            )
            colored_label = DisplayUtils.color_text(label, color)
            print(f"\n{colored_label} ({result['url']})")
            
            DisplayUtils.print_first_lines(
                result['content'], 
                max_lines, 
                max_line_length
            )
            print(" ")
            print("-" * 80)
        
        # Scan avec affichage immédiat
        results = self.http_scanner.scan_endpoints(
            base_url, 
            self.config.endpoints,
            callback=display_result
        )
        
        if found_count[0] == 0:
            print("\nAucun endpoint accessible trouvé.\n")


def main():
    """Point d'entrée principal du programme"""
    os.system('clear')
    
    # Chargement de la configuration
    try:
        config = ConfigManager()
    except SystemExit:
        return
    
    # Affichage du titre
    DisplayUtils.print_ascii_title(config.shodan_colors)
    
    # Demande du domaine
    domain_input = input(
        "  Entrer le nom de domaine à investiguer (ex: domain.com) :\n\n  > "
    ).strip()
    print()
    
    if not domain_input:
        print("❌ Aucun domaine fourni.")
        return
    
    # Options (peut être étendu avec argparse)
    skip_shodan = False
    skip_wayback = False
    
    # Investigation
    try:
        investigator = DomainInvestigator(config)
        investigator.investigate(domain_input, skip_shodan, skip_wayback)
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()