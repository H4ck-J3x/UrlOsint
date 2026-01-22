"""
Module pour l'API Wayback Machine
"""
import requests
from datetime import datetime
from typing import Optional, Dict, Any


class WaybackAPI:
    """Gestionnaire de l'API Wayback Machine"""
    
    BASE_URL = "https://archive.org/wayback/available"
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }
    
    @staticmethod
    def decode_timestamp(timestamp: str) -> str:
        """Convertit un timestamp Wayback en format lisible."""
        try:
            dt = datetime.strptime(timestamp, "%Y%m%d%H%M%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return timestamp
    
    @staticmethod
    def clean_domain(domain: str) -> str:
        """Nettoie le domaine pour la recherche."""
        d = domain.strip()
        if d.startswith("http://"):
            d = d[len("http://"):]
        elif d.startswith("https://"):
            d = d[len("https://"):]
        return d.split("/")[0]
    
    def get_archive_details(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les détails de l'archive la plus proche pour un domaine.
        
        Returns:
            Dict avec url, timestamp, status si disponible, None sinon
        """
        domain = self.clean_domain(domain)
        
        try:
            r = requests.get(
                self.BASE_URL,
                params={"url": domain},
                headers=self.headers,
                timeout=self.timeout
            )
            r.raise_for_status()
            data = r.json()
            
            closest = data.get("archived_snapshots", {}).get("closest")
            
            if closest and closest.get("available") and closest.get("status") == "200":
                return {
                    "url": closest["url"],
                    "timestamp": closest["timestamp"],
                    "timestamp_readable": self.decode_timestamp(closest["timestamp"]),
                    "status": closest["status"],
                    "domain": domain
                }
        except requests.RequestException as e:
            return {"error": f"Erreur lors de la requête: {e}", "domain": domain}
        except Exception as e:
            return {"error": f"Erreur inattendue: {e}", "domain": domain}
        
        return None
    
    def get_calendar(self, domain: str, year: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Récupère le calendrier des snapshots disponibles.
        
        Args:
            domain: Le domaine à rechercher
            year: L'année spécifique (optionnel)
        """
        domain = self.clean_domain(domain)
        url = f"https://web.archive.org/__wb/calendarcaptures/2"
        
        params = {"url": domain, "selected_year": year} if year else {"url": domain}
        
        try:
            r = requests.get(url, params=params, headers=self.headers, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            return {"error": str(e)}