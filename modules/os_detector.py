import asyncio
import logging
import random
import socket
import struct
import time
from typing import Dict, List, Optional, Any, Tuple
from modules.evasion import IPFragmenter


OS_SIGNATURES: Dict[str, Dict[str, Any]] = {
    'Linux 2.6+': {
        'ttl': 64, 'window': 5840, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'wscale', 'nop', 'nop', 'sackok', 'timestamp'],
    },
    'Linux 3.x': {
        'ttl': 64, 'window': 29200, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'wscale', 'nop', 'nop', 'sackok', 'timestamp'],
    },
    'Linux 4.x/5.x': {
        'ttl': 64, 'window': 65535, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'wscale', 'nop', 'nop', 'sackok', 'timestamp'],
    },
    'Windows 10/11': {
        'ttl': 128, 'window': 65535, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'nop', 'sackok', 'timestamp', 'wscale'],
    },
    'Windows 7/8/Server 2008': {
        'ttl': 128, 'window': 8192, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'nop', 'sackok', 'timestamp', 'wscale'],
    },
    'Windows Server 2012/2016': {
        'ttl': 128, 'window': 16384, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'nop', 'sackok', 'timestamp', 'wscale'],
    },
    'macOS 10.x+': {
        'ttl': 64, 'window': 65535, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'nop', 'nop', 'nop', 'sackok', 'timestamp', 'wscale'],
    },
    'FreeBSD': {
        'ttl': 64, 'window': 65535, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'wscale', 'nop', 'sackok', 'timestamp'],
    },
    'OpenBSD': {
        'ttl': 64, 'window': 16384, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'nop', 'sackok', 'timestamp'],
    },
    'Solaris': {
        'ttl': 255, 'window': 8760, 'df': True, 'mss': 1460,
        'options': ['mss', 'nop', 'wscale', 'nop', 'sackok', 'timestamp'],
    },
    'Cisco IOS': {
        'ttl': 255, 'window': 4128, 'df': False, 'mss': 1460,
        'options': ['mss', 'nop', 'nop', 'sackok'],
    },
}

KNOWN_TTL_RANGES = [
    (0, 64, 'Linux/Unix/macOS'),
    (65, 128, 'Windows'),
    (129, 255, 'Cisco/Solaris/HP-UX'),
]


class OSDetector:
    def __init__(self, fragmenter: Optional[IPFragmenter] = None):
        self.logger = logging.getLogger(__name__)
        self.fragmenter = fragmenter

    async def detect_os_by_ttl(self, host: str, port: int = 80) -> Dict[str, Any]:
        result: Dict[str, Any] = {'host': host, 'method': 'ttl_analysis', 'confidence': 'low'}
        try:
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(None, lambda: _create_tcp_syn(host, port))
            if not sock:
                return result
            try:
                sock.settimeout(5)
                raw_data = sock.recv(1024)
                ttl = _parse_ttl(raw_data)
                window = _parse_window_size(raw_data)
                df = _parse_df(raw_data)
                if ttl:
                    result['ttl'] = ttl
                    result['window_size'] = window
                    result['df_bit'] = df
                    matches = _match_os_signature(ttl, window, df)
                    if matches:
                        result['guesses'] = matches
                        result['confidence'] = 'medium'
                        os_family = _classify_os_family(ttl)
                        if os_family:
                            result['os_family'] = os_family
                    else:
                        os_family = _classify_os_family(ttl)
                        if os_family:
                            result['os_family'] = os_family
                            result['guesses'] = [f"{os_family} (TTL-based estimate)"]
                            result['confidence'] = 'low'
            except socket.timeout:
                self.logger.debug(f"Timeout waiting for SYN-ACK from {host}:{port}")
            finally:
                sock.close()
        except Exception as e:
            self.logger.debug(f"OS detection failed for {host}:{port}: {e}")
        return result

    async def detect_os_by_banner(self, banner: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {'method': 'banner_analysis', 'confidence': 'low'}
        banner_lower = banner.lower()
        if 'ubuntu' in banner_lower:
            result['os_family'] = 'Linux (Ubuntu)'
            result['confidence'] = 'high'
        elif 'debian' in banner_lower:
            result['os_family'] = 'Linux (Debian)'
            result['confidence'] = 'high'
        elif 'centos' in banner_lower or 'red hat' in banner_lower or 'rhel' in banner_lower:
            result['os_family'] = 'Linux (RHEL/CentOS)'
            result['confidence'] = 'high'
        elif 'windows' in banner_lower:
            result['os_family'] = 'Windows'
            if '10.0' in banner:
                result['os_family'] = 'Windows 10/11 or Server 2016+'
            elif '6.1' in banner:
                result['os_family'] = 'Windows 7/Server 2008 R2'
            elif '6.2' in banner:
                result['os_family'] = 'Windows 8/Server 2012'
            elif '6.3' in banner:
                result['os_family'] = 'Windows 8.1/Server 2012 R2'
            result['confidence'] = 'high'
        elif 'freebsd' in banner_lower:
            result['os_family'] = 'FreeBSD'
            result['confidence'] = 'high'
        elif 'darwin' in banner_lower or 'macos' in banner_lower:
            result['os_family'] = 'macOS'
            result['confidence'] = 'high'
        elif 'sunos' in banner_lower or 'solaris' in banner_lower:
            result['os_family'] = 'Solaris'
            result['confidence'] = 'high'
        return result


def _create_tcp_syn(host: str, port: int) -> Optional[socket.socket]:
    if isinstance(host, str):
        host = socket.gethostbyname(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except (OSError, AttributeError):
        sock.close()
        alt_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        alt_sock.settimeout(5)
        try:
            alt_sock.connect((host, port))
            alt_sock.close()
            return None
        except Exception:
            alt_sock.close()
            return None
    seq = random.randint(1000, 9999)
    src_port = random.randint(1024, 65535)
    packet = _build_syn_packet(src_port, port, seq)
    try:
        sock.sendto(packet, (host, 0))
        return sock
    except PermissionError:
        sock.close()
        alt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        alt.settimeout(5)
        try:
            alt.connect((host, port))
            alt.close()
        except Exception:
            alt.close()
        return None
    except Exception as e:
        sock.close()
        return None


def _build_syn_packet(src_port: int, dst_port: int, seq: int) -> bytes:
    data_offset = 5
    reserved = 0
    flags = 0x02
    window = socket.htons(65535)
    checksum = 0
    urgent_ptr = 0
    offset_res = (data_offset << 4) | reserved
    tcp_header = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq, 0,
        offset_res, flags, window, checksum, urgent_ptr
    )
    pseudo_hdr = struct.pack('!4s4sBBH', b'\x00' * 4, b'\x00' * 4, 0, socket.IPPROTO_TCP, len(tcp_header))
    checksum = _compute_checksum(pseudo_hdr + tcp_header)
    tcp_header = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq, 0,
        offset_res, flags, window, checksum, urgent_ptr
    )
    return tcp_header


def _compute_checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def _parse_ttl(data: bytes) -> Optional[int]:
    ip_header_len = (data[0] & 0x0F) * 4
    if len(data) < ip_header_len + 1:
        return None
    return data[8]


def _parse_window_size(data: bytes) -> Optional[int]:
    ip_header_len = (data[0] & 0x0F) * 4
    tcp_start = ip_header_len
    if len(data) < tcp_start + 16:
        return None
    win_bytes = data[tcp_start+14:tcp_start+16]
    return struct.unpack('!H', win_bytes)[0]


def _parse_df(data: bytes) -> Optional[bool]:
    if len(data) < 7:
        return None
    flags_fragment = struct.unpack('!H', data[6:8])[0]
    return bool(flags_fragment & 0x4000)


def _match_os_signature(ttl: int, window: int, df: bool) -> List[str]:
    matches = []
    for os_name, sig in OS_SIGNATURES.items():
        score = 0
        if sig['ttl'] == ttl:
            score += 2
        ttl_range = _get_ttl_range(ttl)
        if ttl_range and ttl_range == _get_ttl_range(sig['ttl']):
            score += 1
        if abs(sig['window'] - window) < 1000:
            score += 2
        elif abs(sig['window'] - window) < 5000:
            score += 1
        if sig['df'] == df:
            score += 1
        if score >= 4:
            matches.append((os_name, score))
    matches.sort(key=lambda x: -x[1])
    return [m[0] for m in matches[:3]]


def _get_ttl_range(ttl: int) -> Optional[str]:
    for lo, hi, name in KNOWN_TTL_RANGES:
        if lo <= ttl <= hi:
            return name
    return None


def _classify_os_family(ttl: int) -> str:
    family = _get_ttl_range(ttl)
    return family or 'Unknown'
