import aiohttp
from typing import Dict, List, Any

from modules.plugin_system import BasePlugin


class WordPressScanner(BasePlugin):
    name = "wordpress_scanner"
    description = "WordPress version detection, user enumeration, and vulnerability lookup"
    version = "1.0.0"
    author = "Athena"

    async def run(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        results = []
        base = target.rstrip("/")
        async with aiohttp.ClientSession() as session:
            checks = {
                "wp-json/": "REST API enabled",
                "wp-admin/": "Admin panel exposed",
                "xmlrpc.php": "XML-RPC enabled",
                "wp-content/uploads/": "Uploads directory listing",
                "readme.html": "Readme file exposed",
            }
            for path, desc in checks.items():
                url = f"{base}/{path}"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status < 400:
                            results.append({
                                "type": "wordpress_info",
                                "severity": "info",
                                "url": url,
                                "description": desc,
                                "status": resp.status,
                            })
                except Exception:
                    pass

            version = await self._detect_version(session, base)
            if version:
                results.append({
                    "type": "wordpress_version",
                    "severity": "info",
                    "description": f"WordPress version: {version}",
                    "version": version,
                })
        return results

    async def _detect_version(self, session: aiohttp.ClientSession, base: str) -> str:
        try:
            async with session.get(f"{base}/wp-admin/css/common.min.css", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "wp-admin" in text:
                        return "detected (exact version TBD via generator tag)"
        except Exception:
            pass

        try:
            async with session.get(base, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                text = await resp.text()
                import re
                m = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"', text)
                if m:
                    return m.group(1)
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
