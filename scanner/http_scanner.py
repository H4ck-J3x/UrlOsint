"""
Module pour le scan HTTP des endpoints
"""
import requests
from typing import List, Tuple, Optional, Dict, Any


class HTTPScanner:
    """Scanner pour les endpoints HTTP"""
    
    def __init__(self, headers: Dict[str, str], timeout: int = 5):
        self.headers = headers
        self.timeout = timeout
    
    @staticmethod
    def ensure_scheme(domain_raw: str) -> str:
        """Ajoute le schéma HTTPS si absent."""
        domain_raw = domain_raw.strip()
        if domain_raw.startswith("http://") or domain_raw.startswith("https://"):
            return domain_raw.rstrip("/")
        return "https://" + domain_raw.rstrip("/")
    
    @staticmethod
    def is_probably_text(content_type: str) -> bool:
        """Vérifie si le content-type est probablement du texte."""
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
    
    @staticmethod
    def is_likely_html_fallback(text: str) -> bool:
        """Détecte si le contenu est probablement du HTML."""
        text_lower = text.strip().lower()
        return (
            "<!doctype html" in text_lower or
            text_lower.startswith("<html") or
            "<html" in text_lower[:200]
        )
    
    def try_fetch(self, url: str) -> Optional[requests.Response]:
        """Tente de récupérer une URL."""
        try:
            r = requests.get(
                url, 
                headers=self.headers, 
                timeout=self.timeout, 
                allow_redirects=True
            )
            return r if r.status_code == 200 else None
        except requests.RequestException:
            return None
    
    def scan_endpoints(
        self, 
        base_url: str, 
        endpoints: List[Tuple[str, str, str]],
        callback=None
    ) -> List[Dict[str, Any]]:
        """
        Scanne une liste d'endpoints pour un domaine.
        
        Args:
            base_url: URL de base (avec schéma)
            endpoints: Liste de tuples (name, path, description)
            callback: Fonction appelée pour chaque résultat trouvé
            
        Returns:
            Liste de dictionnaires contenant les résultats
        """
        results = []
        
        for name, path, description in endpoints:
            url = base_url + path
            response = self.try_fetch(url)
            
            if not response:
                continue
            
            # Lecture du contenu
            try:
                content = response.text
            except Exception:
                try:
                    content = response.content.decode(
                        response.encoding or "utf-8", 
                        errors="replace"
                    )
                except Exception:
                    continue
            
            # Ignorer les pages HTML de fallback
            if self.is_likely_html_fallback(content):
                continue
            
            result = {
                "name": name,
                "path": path,
                "url": url,
                "content": content,
                "description": description,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", "")
            }
            
            results.append(result)
            
            # Appel du callback immédiatement si fourni
            if callback:
                callback(result, len(results) - 1)
        
        return results