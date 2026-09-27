from typing import Dict, List, Any

from modules.plugin_system import BasePlugin

try:
    import dns.resolver
    import dns.zone
    import dns.query
except ImportError:
    dns = None


class DNSEnumerator(BasePlugin):
    name = "dns_enum"
    description = "DNS enumeration: zone transfer, subdomain brute, SPF/DMARC checks"
    version = "1.0.0"
    author = "Athena"

    COMMON_SUBDOMAINS = [
        "www", "mail", "admin", "blog", "api", "dev", "staging",
        "beta", "app", "cdn", "static", "assets", "img", "css",
        "js", "docs", "support", "help", "forum", "community",
        "shop", "store", "portal", "secure", "vpn", "remote",
        "webmail", "smtp", "pop3", "imap", "ns1", "ns2", "mx",
    ]

    async def run(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        results = []
        domain = target.strip().lower()
        for prefix in ["http://", "https://"]:
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0].split(":")[0]

        if dns is None:
            results.append({
                "type": "dns_error",
                "severity": "warning",
                "description": "dnspython not installed, skipping DNS enumeration",
            })
            return results

        zone = await self._try_zone_transfer(domain)
        if zone:
            results.append({
                "type": "dns_zone_transfer",
                "severity": "critical",
                "description": f"Zone transfer successful on {domain}",
                "records": zone,
            })

        subdomains = await self._bruteforce_subdomains(domain)
        for sd in subdomains:
            results.append({
                "type": "dns_subdomain",
                "severity": "info",
                "description": f"Subdomain found: {sd}",
            })

        spf = await self._check_spf(domain)
        if spf:
            results.append({
                "type": "dns_spf",
                "severity": "low",
                "description": f"SPF record: {spf}",
            })

        dmarc = await self._check_dmarc(domain)
        if dmarc:
            results.append({
                "type": "dns_dmarc",
                "severity": "low",
                "description": f"DMARC record: {dmarc}",
            })

        return results

    async def _try_zone_transfer(self, domain: str) -> List[str]:
        records = []
        try:
            ns = dns.resolver.resolve(domain, "NS")
            for ns_record in ns:
                ns_name = str(ns_record.target).rstrip(".")
                try:
                    ns_ip = dns.resolver.resolve(ns_name, "A")[0].to_text()
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                    for name, node in zone.nodes.items():
                        records.append(str(name))
                except Exception:
                    pass
        except Exception:
            pass
        return records

    async def _bruteforce_subdomains(self, domain: str) -> List[str]:
        found = []
        for sub in self.COMMON_SUBDOMAINS:
            try:
                target = f"{sub}.{domain}"
                dns.resolver.resolve(target, "A")
                found.append(target)
            except Exception:
                pass
        return found

    async def _check_spf(self, domain: str) -> str:
        try:
            txt = dns.resolver.resolve(domain, "TXT")
            for record in txt:
                text = str(record)
                if "v=spf1" in text:
                    return text
        except Exception:
            pass
        return ""

    async def _check_dmarc(self, domain: str) -> str:
        try:
            txt = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in txt:
                text = str(record)
                if "v=DMARC1" in text:
                    return text
        except Exception:
            pass
        return ""

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
        }
