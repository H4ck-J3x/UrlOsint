"""
Module pour l'API Shodan
"""
import os
import socket
import shodan
from typing import List, Dict, Any, Optional


class ShodanAPI:
    """Gestionnaire de l'API Shodan"""

    MAX_CVES = 20  # 🔒 Limite globale de vulnérabilités

    def __init__(self, api_key: Optional[str] = None, search_limit: int = 100):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Clé Shodan non fournie. Définissez SHODAN_API_KEY ou passez api_key."
            )
        self.client = shodan.Shodan(self.api_key)
        self.search_limit = search_limit

    @staticmethod
    def clean_domain(domain: str) -> str:
        """Normalise l'entrée et retire schéma / chemin."""
        d = domain.strip()
        if d.startswith("http://"):
            d = d[len("http://"):]
        elif d.startswith("https://"):
            d = d[len("https://"):]
        return d.split("/")[0].lower()

    @staticmethod
    def resolve_ips(domain: str) -> List[str]:
        """Résout le nom de domaine en adresses IP (IPv4)."""
        domain = ShodanAPI.clean_domain(domain)
        ips = set()
        try:
            for res in socket.getaddrinfo(domain, None):
                ip = res[4][0]
                if "." in ip:
                    ips.add(ip)
        except Exception:
            pass
        return sorted(ips)

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Recherche les informations Shodan pour un domaine."""
        domain = self.clean_domain(domain)

        result: Dict[str, Any] = {
            "domain": domain,
            "ips_from_dns": self.resolve_ips(domain),
            "filtered_hosts": {},
            "cves": set(),
            "errors": []
        }

        # 1️⃣ Recherche hostname:"domain"
        try:
            query = f'hostname:"{domain}"'
            search_res = self.client.search(query, limit=self.search_limit)
            matches = search_res.get("matches", [])
        except shodan.APIError as e:
            result["errors"].append(f"Shodan search error: {e}")
            matches = []
        except Exception as e:
            result["errors"].append(f"Shodan search unexpected error: {e}")
            matches = []

        # 2️⃣ Filtrage des résultats
        for m in matches:
            if len(result["cves"]) >= self.MAX_CVES:
                break

            hostnames = m.get("hostnames") or []
            ip = m.get("ip_str")
            keep = False
            kept_hostname = None

            for hn in hostnames:
                if domain in hn or hn.endswith(domain):
                    keep = True
                    kept_hostname = hn
                    break

            if not keep:
                continue

            key = kept_hostname or ip or "(unknown)"
            entry = result["filtered_hosts"].setdefault(
                key,
                {"ips": set(), "ports": set(), "vulns": set()}
            )

            if ip:
                entry["ips"].add(ip)

            if m.get("port"):
                entry["ports"].add(m.get("port"))

            for c in m.get("vulns") or []:
                if len(result["cves"]) >= self.MAX_CVES:
                    break
                if isinstance(c, str) and c.upper().startswith("CVE-"):
                    c = c.upper()
                    entry["vulns"].add(c)
                    result["cves"].add(c)

        # 3️⃣ Récupération des infos par IP
        ips_to_check = set(result["ips_from_dns"])
        for h in result["filtered_hosts"].values():
            ips_to_check.update(h["ips"])

        for ip in sorted(ips_to_check):
            if len(result["cves"]) >= self.MAX_CVES:
                break

            try:
                host_info = self.client.host(ip)
                ports = host_info.get("ports", [])

                for hval in result["filtered_hosts"].values():
                    if ip not in hval["ips"]:
                        continue

                    for p in ports:
                        hval["ports"].add(p)

                    for c in host_info.get("vulns") or []:
                        if len(result["cves"]) >= self.MAX_CVES:
                            break
                        if isinstance(c, str) and c.upper().startswith("CVE-"):
                            c = c.upper()
                            hval["vulns"].add(c)
                            result["cves"].add(c)

            except shodan.APIError as e:
                result["errors"].append(f"Shodan host error for {ip}: {e}")
            except Exception as e:
                result["errors"].append(f"Shodan host unexpected error for {ip}: {e}")

        # 4️⃣ Conversion des sets en listes
        for v in result["filtered_hosts"].values():
            v["ips"] = sorted(v["ips"])
            v["ports"] = sorted(v["ports"])
            v["vulns"] = sorted(v["vulns"])[:self.MAX_CVES]

        result["cves"] = sorted(result["cves"])[:self.MAX_CVES]

        return result
