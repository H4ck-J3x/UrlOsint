"""
Module de gestion de la configuration
"""
import json
import sys
from typing import Dict, Any, List, Tuple


class ConfigManager:
    """Gestionnaire de configuration centralisé"""
    
    def __init__(self, api_config_file: str = "api.json", endpoints_file: str = "endpoints.json"):
        self.api_config = self._load_api_config(api_config_file)
        self.endpoints = self._load_endpoints(endpoints_file)
    
    def _load_api_config(self, filename: str) -> Dict[str, Any]:
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
    
    def _load_endpoints(self, filename: str) -> List[Tuple[str, str, str]]:
        """Charge les endpoints depuis le fichier JSON."""
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
    
    @property
    def http_settings(self) -> Dict[str, Any]:
        return self.api_config["http_settings"]
    
    @property
    def shodan_settings(self) -> Dict[str, Any]:
        return self.api_config["shodan"]
    
    @property
    def display_settings(self) -> Dict[str, Any]:
        return self.api_config["display_settings"]
    
    @property
    def gradient_colors(self) -> List[Tuple[int, int, int]]:
        return [tuple(color) for color in self.display_settings["gradient_colors"]]
    
    @property
    def shodan_colors(self) -> Dict[str, Tuple[int, int, int]]:
        return {
            key: tuple(value) 
            for key, value in self.display_settings["shodan_colors"].items()
        }