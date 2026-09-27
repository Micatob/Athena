import asyncio
import logging
import random
import socket
import string
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field


USER_AGENTS: List[str] = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux i686; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36',
    'curl/8.4.0',
    'Wget/1.21.4',
    'Python-aiohttp/3.9.0',
    'Go-http-client/2.0',
]


@dataclass
class ProxyConfig:
    http: Optional[str] = None
    https: Optional[str] = None
    socks4: Optional[str] = None
    socks5: Optional[str] = None
    tor: bool = False
    tor_control_port: int = 9051
    tor_socks_port: int = 9050

    def is_active(self) -> bool:
        return any([self.http, self.https, self.socks4, self.socks5, self.tor])


@dataclass
class EvasionConfig:
    user_agent_rotation: bool = True
    random_delay_min: float = 1.0
    random_delay_max: float = 5.0
    jitter: bool = True
    jitter_percent: float = 0.3
    noise_headers: bool = True
    ip_fragmentation: bool = False
    fragment_size: int = 128
    decoy_sources: bool = False
    decoy_ips: List[str] = field(default_factory=list)
    proxy: Optional[ProxyConfig] = None
    rate_limit_rps: float = 5.0


class EvasionEngine:
    def __init__(self, config: Optional[EvasionConfig] = None):
        self.config = config or EvasionConfig()
        self.logger = logging.getLogger(__name__)
        self._user_agent_pool = USER_AGENTS[:]
        self._current_ua: Optional[str] = None

    def get_random_user_agent(self) -> str:
        if not self.config.user_agent_rotation:
            return USER_AGENTS[0]
        self._current_ua = random.choice(self._user_agent_pool)
        return self._current_ua

    def get_delay(self) -> float:
        base = random.uniform(self.config.random_delay_min, self.config.random_delay_max)
        if self.config.jitter:
            jitter_amount = base * self.config.jitter_percent
            base += random.uniform(-jitter_amount, jitter_amount)
        return max(0.1, base)

    def add_noise_headers(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        if headers is None:
            headers = {}
        if not self.config.noise_headers:
            return headers
        random_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        noise = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'fr-FR,fr;q=0.9', 'de-DE,de;q=0.9']),
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'X-Forwarded-For': random_ip,
            'X-Real-IP': random_ip,
            'Client-IP': random_ip,
            'True-Client-IP': random_ip,
        }
        noise.update(headers)
        return noise

    async def apply_proxy(self, session_args: Dict[str, Any]) -> Dict[str, Any]:
        if not self.config.proxy or not self.config.proxy.is_active():
            return session_args
        cfg = self.config.proxy
        if cfg.tor:
            connector_args = session_args.get('connector_args', {})
            proxies = {
                'http': f'socks5://127.0.0.1:{cfg.tor_socks_port}',
                'https': f'socks5://127.0.0.1:{cfg.tor_socks_port}',
            }
            session_args['proxies'] = proxies
            self.logger.info("Tor proxy configured on port %d", cfg.tor_socks_port)
        else:
            proxies = {}
            if cfg.http:
                proxies['http'] = cfg.http
            if cfg.https:
                proxies['https'] = cfg.https
            if proxies:
                session_args['proxies'] = proxies
        return session_args

    async def renew_tor_circuit(self) -> bool:
        if not self.config.proxy or not self.config.proxy.tor:
            return False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', self.config.proxy.tor_control_port),
                timeout=5
            )
            auth_cmd = b'AUTHENTICATE ""\r\n'
            writer.write(auth_cmd)
            await writer.drain()
            await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.write(b'SIGNAL NEWNYM\r\n')
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=3)
            writer.close()
            if b'250' in response:
                self.logger.info("Tor circuit renewed")
                await asyncio.sleep(2)
                return True
        except Exception as e:
            self.logger.debug("Tor circuit renewal failed: %s", e)
        return False

    def fragment_packet(self, data: bytes) -> List[bytes]:
        if not self.config.ip_fragmentation:
            return [data]
        fragments = []
        frag_size = self.config.fragment_size
        for i in range(0, len(data), frag_size):
            chunk = data[i:i + frag_size]
            fragments.append(chunk)
        return fragments

    def generate_decoy_sources(self, real_ip: str, count: int = 5) -> List[str]:
        sources = []
        decoys = [
            '10.0.0.1', '10.0.0.2', '172.16.0.1', '192.168.1.1', '192.168.1.100',
        ]
        sources.extend(decoys[:count])
        sources.append(real_ip)
        random.shuffle(sources)
        return sources


class IPFragmenter:
    def __init__(self, fragment_size: int = 128):
        self.fragment_size = fragment_size

    def fragment(self, data: bytes) -> List[bytes]:
        fragments = []
        for i in range(0, len(data), self.fragment_size):
            fragments.append(data[i:i + self.fragment_size])
        return fragments

    def defragment(self, fragments: List[bytes]) -> bytes:
        return b''.join(fragments)
