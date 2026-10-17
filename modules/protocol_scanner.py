import asyncio
import logging
import socket
import struct
import base64
import hashlib
import random
import re
import ssl
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field


@dataclass
class ServiceCredential:
    service: str
    host: str
    port: int
    username: str
    password: str
    success: bool = False


DEFAULT_CREDENTIALS: Dict[str, List[Tuple[str, str]]] = {
    'ftp': [('anonymous', 'anonymous'), ('anonymous', 'guest'), ('ftp', 'ftp'), ('admin', 'admin'), ('root', 'root')],
    'ssh': [('root', 'root'), ('admin', 'admin'), ('root', 'toor'), ('admin', 'password'), ('user', 'user')],
    'mysql': [('root', ''), ('root', 'root'), ('admin', 'admin'), ('test', 'test'), ('mysql', 'mysql')],
    'postgresql': [('postgres', 'postgres'), ('postgres', 'admin'), ('admin', 'admin'), ('postgres', '')],
    'mssql': [('sa', ''), ('sa', 'sa'), ('sa', 'admin'), ('admin', 'admin'), ('sa', 'Password123')],
    'smtp': [('admin', 'admin'), ('root', 'root'), ('postmaster', 'postmaster'), ('test', 'test')],
    'pop3': [('admin', 'admin'), ('root', 'root'), ('test', 'test'), ('user', 'password')],
    'imap': [('admin', 'admin'), ('root', 'root'), ('test', 'test'), ('user', 'password')],
    'smb': [('guest', ''), ('admin', 'admin'), ('administrator', 'password'), ('user', 'user')],
    'redis': [('default', ''), ('admin', 'admin'), ('root', 'root')],
    'telnet': [('admin', 'admin'), ('root', 'root'), ('user', 'user'), ('test', 'test'), ('guest', 'guest')],
}

#: Ports where TLS is implicit (connect with TLS from byte 0) vs STARTTLS-upgradable.
IMPLICIT_TLS_PORTS = {465, 993, 995, 2083, 2087, 2096, 443, 8443}
STARTTLS_PORTS = {25, 587, 143, 110, 21}


COMMON_SNMP_COMMUNITIES = ['public', 'private', 'manager', 'admin', 'community', 'secret', 'snmp']


class SMBEnumerator:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def enumerate(self, host: str, port: int = 445) -> Dict[str, Any]:
        result: Dict[str, Any] = {'host': host, 'port': port, 'accessible': False}
        try:
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
            if not sock:
                return result
            try:
                nbss = _build_netbios_session_request()
                sock.sendall(nbss)
                resp = _recv_all(sock, 1024, self.timeout)
                if resp and len(resp) > 4:
                    result['netbios'] = {'session_established': True}
                    smb_neg = _build_smb_negotiate()
                    sock.sendall(smb_neg)
                    neg_resp = _recv_all(sock, 4096, self.timeout)
                    if neg_resp and len(neg_resp) > 64:
                        result['accessible'] = True
                        result['dialect'] = _parse_smb_dialect(neg_resp)
                        result['os_version'] = _parse_smb_os(neg_resp)
            finally:
                sock.close()
        except Exception as e:
            self.logger.debug("SMB enumeration failed for %s: %s", host, e)
        return result

    async def check_guest_access(self, host: str, port: int = 445) -> bool:
        try:
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
            if not sock:
                return False
            try:
                sock.sendall(_build_netbios_session_request())
                _recv_all(sock, 1024, self.timeout)
                sock.sendall(_build_smb_negotiate())
                neg_resp = _recv_all(sock, 4096, self.timeout)
                if not neg_resp:
                    return False
                sock.sendall(_build_smb_session_setup('guest', ''))
                auth_resp = _recv_all(sock, 4096, self.timeout)
                if auth_resp and len(auth_resp) > 64:
                    nt_status = struct.unpack_from('<I', auth_resp, 9)[0]
                    return nt_status == 0
                return False
            finally:
                sock.close()
        except Exception:
            return False


class SNMPEnumerator:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def enumerate(self, host: str, port: int = 161) -> Dict[str, Any]:
        result: Dict[str, Any] = {'host': host, 'port': port, 'accessible': False, 'communities': []}
        for community in COMMON_SNMP_COMMUNITIES:
            try:
                accessible = await self._check_community(host, port, community)
                if accessible:
                    result['accessible'] = True
                    result['communities'].append(community)
                    if not result.get('community'):
                        result['community'] = community
                    oid_result = await self._walk_system(host, port, community)
                    if oid_result:
                        result.update(oid_result)
                    break
            except Exception as e:
                self.logger.debug("SNMP community check failed for %s: %s", host, e)
        return result

    async def _check_community(self, host: str, port: int, community: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            pkt = _build_snmp_get_request(community, '1.3.6.1.2.1.1.1.0')
            await loop.run_in_executor(None, lambda: sock.sendto(pkt, (host, port)))
            resp, addr = await loop.run_in_executor(None, lambda: sock.recvfrom(4096))
            return len(resp) > 20
        except socket.timeout:
            return False
        except Exception:
            return False
        finally:
            sock.close()

    async def _walk_system(self, host: str, port: int, community: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        oids = {
            'system_desc': '1.3.6.1.2.1.1.1.0',
            'system_name': '1.3.6.1.2.1.1.5.0',
            'system_uptime': '1.3.6.1.2.1.1.3.0',
            'system_contact': '1.3.6.1.2.1.1.4.0',
            'system_location': '1.3.6.1.2.1.1.6.0',
        }
        for key, oid in oids.items():
            try:
                val = await self._get_oid(host, port, community, oid)
                if val:
                    result[key] = val
            except Exception:
                pass
        return result

    async def _get_oid(self, host: str, port: int, community: str, oid: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            pkt = _build_snmp_get_request(community, oid)
            await loop.run_in_executor(None, lambda: sock.sendto(pkt, (host, port)))
            resp, addr = await loop.run_in_executor(None, lambda: sock.recvfrom(4096))
            val = _parse_snmp_response(resp)
            return val
        except Exception:
            return None
        finally:
            sock.close()


class SMTPEnumerator:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def enumerate(self, host: str, port: int = 25) -> Dict[str, Any]:
        result: Dict[str, Any] = {'host': host, 'port': port, 'accessible': False}
        try:
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
            if not sock:
                return result
            try:
                if port in (465, 995, 993):
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = await loop.run_in_executor(None, ctx.wrap_socket, sock, host)
                    except Exception:
                        return result
                banner = _recv_all(sock, 1024, self.timeout)
                if banner:
                    result['accessible'] = True
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    result['transport'] = 'TLS' if port in (465, 995, 993) else 'plain'
                    commands = {
                        'vrfy_root': ('VRFY root\r\n', 'VRFY'),
                        'vrfy_admin': ('VRFY admin\r\n', 'VRFY'),
                        'expn': ('EXPN root\r\n', 'EXPN'),
                        'help': ('HELP\r\n', 'HELP'),
                    }
                    for key, (cmd, _) in commands.items():
                        try:
                            sock.sendall(cmd.encode())
                            resp = _recv_all(sock, 1024, 3)
                            if resp:
                                result[key] = resp.decode('utf-8', errors='ignore').strip()
                        except Exception:
                            pass
            finally:
                sock.close()
        except Exception as e:
            self.logger.debug("SMTP enumeration failed for %s: %s", host, e)
        return result


class POP3Enumerator:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def enumerate(self, host: str, port: int = 110) -> Dict[str, Any]:
        result: Dict[str, Any] = {'host': host, 'port': port, 'accessible': False}
        try:
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
            if not sock:
                return result
            try:
                banner = _recv_all(sock, 1024, self.timeout)
                if banner:
                    result['accessible'] = True
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    commands = {
                        'capabilities': ('CAPA\r\n', 'CAPA'),
                        'stat': ('STAT\r\n', 'STAT'),
                    }
                    for key, (cmd, _) in commands.items():
                        try:
                            sock.sendall(cmd.encode())
                            resp = _recv_all(sock, 4096, 3)
                            if resp:
                                result[key] = resp.decode('utf-8', errors='ignore').strip()
                        except Exception:
                            pass
            finally:
                sock.close()
        except Exception as e:
            self.logger.debug("POP3 enumeration failed for %s: %s", host, e)
        return result


class IMAPEnumerator:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def enumerate(self, host: str, port: int = 143) -> Dict[str, Any]:
        result: Dict[str, Any] = {'host': host, 'port': port, 'accessible': False}
        try:
            loop = asyncio.get_event_loop()
            sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
            if not sock:
                return result
            try:
                banner = _recv_all(sock, 4096, self.timeout)
                if banner:
                    result['accessible'] = True
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                    try:
                        sock.sendall(b'A1 CAPABILITY\r\n')
                        resp = _recv_all(sock, 4096, 3)
                        if resp:
                            result['capability'] = resp.decode('utf-8', errors='ignore').strip()
                    except Exception:
                        pass
            finally:
                sock.close()
        except Exception as e:
            self.logger.debug("IMAP enumeration failed for %s: %s", host, e)
        return result


class FTPBruteforcer:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def check_anonymous(self, host: str, port: int = 21) -> bool:
        # Real servers accept different anon passwords: blank, email, guest.
        # Trying only 'anonymous' misses most open servers.
        for pwd in ('anonymous', '', 'guest', 'anonymous@test.com', 'ftp@test.com'):
            try:
                if await self.try_login(host, port, 'anonymous', pwd):
                    return True
            except Exception:
                continue
        return False

    async def try_login(self, host: str, port: int, username: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            _recv_all(sock, 1024, self.timeout)
            sock.sendall(f'USER {username}\r\n'.encode())
            _recv_all(sock, 1024, self.timeout)
            sock.sendall(f'PASS {password}\r\n'.encode())
            resp = _recv_all(sock, 1024, self.timeout)
            if resp:
                code = resp[:3].decode('utf-8', errors='ignore')
                # After PASS only 2xx (230 Logged in) is success.
                # 3xx here means ACCT needed, not logged in.
                return code.startswith('2')
        except Exception:
            return False
        finally:
            sock.close()
        return False


class SSHBruteforcer:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def try_login(self, host: str, port: int, username: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            banner = _recv_all(sock, 4096, 5)
            if not banner:
                return False
            ssh_version = banner.decode('utf-8', errors='ignore').strip()
            sock.sendall(b'SSH-2.0-OpenSSH_9.0\r\n')
            _recv_all(sock, 4096, 3)
            return False
        except Exception:
            return False
        finally:
            sock.close()

    async def get_banner(self, host: str, port: int = 22) -> Optional[str]:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return None
        try:
            banner = _recv_all(sock, 4096, 5)
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return None
        finally:
            sock.close()
        return None


class MySQLBruteforcer:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def try_login(self, host: str, port: int, username: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            handshake = _recv_all(sock, 4096, self.timeout)
            if not handshake or len(handshake) < 4:
                return False
            if handshake[4] == 0x0a:
                auth_pkt = _build_mysql_auth(handshake, username, password)
                sock.sendall(auth_pkt)
                auth_resp = _recv_all(sock, 4096, self.timeout)
                if auth_resp and len(auth_resp) > 4:
                    return auth_resp[4] == 0x00
            return False
        except Exception:
            return False
        finally:
            sock.close()


class PostgreSQLBruteforcer:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def try_login(self, host: str, port: int, username: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            startup = _build_pg_startup(username, 'athena')
            sock.sendall(startup)
            resp = _recv_all(sock, 4096, self.timeout)
            if not resp:
                return False
            if resp[0] == ord('R'):
                auth_data = resp[5:]
                auth_pkt = _build_pg_password(auth_data, password)
                sock.sendall(auth_pkt)
                auth_resp = _recv_all(sock, 4096, self.timeout)
                if auth_resp:
                    return auth_resp[0] == ord('R') or auth_resp[0] == ord('K')
            return False
        except Exception:
            return False
        finally:
            sock.close()


class MSSQLBruteforcer:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def try_login(self, host: str, port: int, username: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            prelogin = _build_mssql_prelogin()
            sock.sendall(prelogin)
            pre_resp = _recv_all(sock, 4096, self.timeout)
            if not pre_resp:
                return False
            login_pkt = _build_mssql_login(username, password)
            sock.sendall(login_pkt)
            login_resp = _recv_all(sock, 4096, self.timeout)
            if login_resp and len(login_resp) > 8:
                return login_resp[8] == 0x01
            return False
        except Exception:
            return False
        finally:
            sock.close()


class RedisBruteforcer:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def try_auth(self, host: str, port: int, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            sock.sendall(f'AUTH {password}\r\n'.encode())
            resp = _recv_all(sock, 1024, self.timeout)
            if resp:
                return b'+OK' in resp
        except Exception:
            return False
        finally:
            sock.close()
        return False


class SMTPBruteforcer:
    """SMTP AUTH (PLAIN/LOGIN) with STARTTLS + implicit-TLS awareness.

    Plain bruteforce without TLS fails on every modern server (it refuses
    AUTH over cleartext) — this class upgrades via STARTTLS when offered,
    wraps implicit-TLS ports directly, and reports the transport used.
    """
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def try_login(self, host: str, port: int, username: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            _recv_all(sock, 1024, self.timeout)
            # Implicit TLS ports: wrap immediately
            if port in IMPLICIT_TLS_PORTS:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = await loop.run_in_executor(None, ctx.wrap_socket, sock, host)
                except Exception:
                    return False
                _recv_all(sock, 1024, self.timeout)
            else:
                # EHLO -> STARTTLS upgrade when advertised (ports 25/587)
                try:
                    sock.sendall(b'EHLO athena\r\n')
                    ehlo = _recv_all(sock, 4096, 3)
                    if ehlo and b'STARTTLS' in ehlo.upper():
                        sock.sendall(b'STARTTLS\r\n')
                        resp = _recv_all(sock, 1024, 3)
                        if resp and resp[:3] == b'220':
                            try:
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                sock = await loop.run_in_executor(None, ctx.wrap_socket, sock, host)
                                sock.sendall(b'EHLO athena\r\n')
                                _recv_all(sock, 4096, 3)
                            except Exception:
                                pass
                except Exception:
                    pass
            # AUTH LOGIN exchange
            try:
                sock.sendall(b'AUTH LOGIN\r\n')
                r1 = _recv_all(sock, 1024, 3)
                if not r1 or r1[:3] not in (b'334', b'235'):
                    return False
                if r1[:3] == b'235':
                    return True
                sock.sendall((base64.b64encode(username.encode()).decode() + '\r\n').encode())
                r2 = _recv_all(sock, 1024, 3)
                if not r2 or r2[:3] != b'334':
                    return False
                sock.sendall((base64.b64encode(password.encode()).decode() + '\r\n').encode())
                r3 = _recv_all(sock, 1024, 3)
                return bool(r3 and r3[:3] == b'235')
            except Exception:
                return False
        finally:
            try:
                sock.close()
            except Exception:
                pass


class POP3Bruteforcer:
    """POP3 USER/PASS with STLS + implicit-TLS awareness."""
    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    async def try_login(self, host: str, port: int, username: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            banner = _recv_all(sock, 1024, self.timeout)
            if not banner or not banner.startswith(b'+OK'):
                # Implicit TLS ports may need a wrap first
                if port in IMPLICIT_TLS_PORTS:
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = await loop.run_in_executor(None, ctx.wrap_socket, sock, host)
                        banner = _recv_all(sock, 1024, self.timeout)
                        if not banner or not banner.startswith(b'+OK'):
                            return False
                    except Exception:
                        return False
                else:
                    return False
            # STLS upgrade on plain ports when offered
            if port not in IMPLICIT_TLS_PORTS:
                try:
                    sock.sendall(b'CAPA\r\n')
                    capa = _recv_all(sock, 4096, 3)
                    if capa and b'STLS' in capa.upper():
                        sock.sendall(b'STLS\r\n')
                        r = _recv_all(sock, 1024, 3)
                        if r and r.startswith(b'+OK'):
                            try:
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                sock = await loop.run_in_executor(None, ctx.wrap_socket, sock, host)
                            except Exception:
                                pass
                except Exception:
                    pass
            sock.sendall(f'USER {username}\r\n'.encode())
            r1 = _recv_all(sock, 1024, 3)
            if not r1 or not r1.startswith(b'+OK'):
                return False
            sock.sendall(f'PASS {password}\r\n'.encode())
            r2 = _recv_all(sock, 1024, 3)
            return bool(r2 and r2.startswith(b'+OK'))
        except Exception:
            return False
        finally:
            try:
                sock.close()
            except Exception:
                pass


class IMAPBruteforcer:
    """IMAP LOGIN with STARTTLS + implicit-TLS awareness."""
    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    async def try_login(self, host: str, port: int, username: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            banner = _recv_all(sock, 4096, self.timeout)
            if not banner or b'OK' not in banner.upper():
                if port in IMPLICIT_TLS_PORTS:
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = await loop.run_in_executor(None, ctx.wrap_socket, sock, host)
                        banner = _recv_all(sock, 4096, self.timeout)
                        if not banner:
                            return False
                    except Exception:
                        return False
                else:
                    return False
            if port not in IMPLICIT_TLS_PORTS:
                try:
                    sock.sendall(b'A1 CAPABILITY\r\n')
                    capa = _recv_all(sock, 4096, 3)
                    if capa and b'STARTTLS' in capa.upper():
                        sock.sendall(b'A2 STARTTLS\r\n')
                        r = _recv_all(sock, 1024, 3)
                        if r and b'OK' in r.upper():
                            try:
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                sock = await loop.run_in_executor(None, ctx.wrap_socket, sock, host)
                            except Exception:
                                pass
                except Exception:
                    pass
            tag = f'A{random.randint(100, 999)}'
            sock.sendall(f'{tag} LOGIN "{username}" "{password}"\r\n'.encode())
            resp = _recv_all(sock, 4096, 5)
            if not resp:
                return False
            text = resp.decode('utf-8', errors='ignore').upper()
            return f'{tag} OK' in text
        except Exception:
            return False
        finally:
            try:
                sock.close()
            except Exception:
                pass


async def check_anonymous_access(host: str, port: int, service: str, timeout: int = 8) -> Dict[str, Any]:
    """Probe anonymous / no-auth access BEFORE bruteforce. Never raises."""
    out: Dict[str, Any] = {'service': service, 'host': host, 'port': port,
                           'anonymous': False, 'detail': ''}
    try:
        loop = asyncio.get_event_loop()
        if service == 'ftp':
            fb = FTPBruteforcer(timeout)
            ok_pwd = ''
            ok = False
            for pwd in ('anonymous', '', 'guest', 'anonymous@test.com', 'ftp@test.com'):
                try:
                    if await fb.try_login(host, port, 'anonymous', pwd):
                        ok = True
                        ok_pwd = pwd
                        break
                except Exception:
                    continue
            out['anonymous'] = ok
            if ok:
                out['detail'] = f"anonymous:{ok_pwd or 'anonymous'} accepted"
            else:
                out['detail'] = 'anonymous rejected (USER ok, PASS rejected - anon disabled or email-password required)'
        elif service == 'smb':
            smb = SMBEnumerator(timeout)
            ok = await smb.check_guest_access(host, port)
            out['anonymous'] = ok
            out['detail'] = 'guest/null session accepted' if ok else 'guest rejected'
        elif service == 'smtp':
            # Open-relay test: try MAIL FROM / RCPT TO without auth
            sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, timeout))
            if sock:
                try:
                    _recv_all(sock, 1024, timeout)
                    sock.sendall(b'HELO athena\r\n')
                    _recv_all(sock, 1024, 3)
                    sock.sendall(b'MAIL FROM:<athena@test.com>\r\n')
                    m = _recv_all(sock, 1024, 3)
                    sock.sendall(b'RCPT TO:<victim@test.com>\r\n')
                    r = _recv_all(sock, 1024, 3)
                    if r and r[:3] == b'250':
                        out['anonymous'] = True
                        out['detail'] = 'OPEN RELAY — unauthenticated RCPT accepted'
                    else:
                        out['detail'] = 'relay denied (auth required)'
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
        elif service == 'redis':
            sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, timeout))
            if sock:
                try:
                    sock.sendall(b'INFO\r\n')
                    resp = _recv_all(sock, 4096, timeout)
                    if resp and (b'redis_version' in resp.lower() or b'$' in resp[:1]):
                        out['anonymous'] = True
                        out['detail'] = 'NOAUTH — INFO without password returned server info'
                    else:
                        out['detail'] = 'auth required (NOAUTH error)'
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
        elif service == 'snmp':
            snmp = SNMPEnumerator(timeout)
            res = await snmp.enumerate(host, port)
            if res.get('accessible'):
                out['anonymous'] = True
                out['detail'] = f"public community '{res.get('community')}' accepted"
            else:
                out['detail'] = 'no public community'
    except Exception as exc:
        out['detail'] = f'check failed: {exc}'[:200]
    return out


class ServiceBruteforcer:
    def __init__(self, timeout: int = 8, rate_limit: float = 2.0):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.logger = logging.getLogger(__name__)
        self.ftp = FTPBruteforcer(timeout)
        self.ssh = SSHBruteforcer(timeout)
        self.mysql = MySQLBruteforcer(timeout)
        self.postgres = PostgreSQLBruteforcer(timeout)
        self.mssql = MSSQLBruteforcer(timeout)
        self.redis_b = RedisBruteforcer(timeout)
        self.smtp = SMTPEnumerator(timeout)
        self.smb = SMBEnumerator(timeout)
        self.smtp_b = SMTPBruteforcer(timeout)
        self.pop3_b = POP3Bruteforcer(timeout)
        self.imap_b = IMAPBruteforcer(timeout)

    async def bruteforce_service(self, host: str, port: int, service: str,
                                  usernames: List[str], passwords: List[str]) -> List[ServiceCredential]:
        results = []
        if service not in DEFAULT_CREDENTIALS:
            return results
        for default_user, default_pass in DEFAULT_CREDENTIALS[service]:
            ok = await self._try_default(host, port, service, default_user, default_pass)
            if ok:
                results.append(ServiceCredential(service, host, port, default_user, default_pass, True))
                return results
        for username in usernames[:20]:
            for password in passwords[:20]:
                ok = await self._try_default(host, port, service, username, password)
                if ok:
                    results.append(ServiceCredential(service, host, port, username, password, True))
                    return results
                await asyncio.sleep(1.0 / self.rate_limit)
        return results

    async def check_anonymous(self, host: str, port: int, service: str) -> Dict[str, Any]:
        """Public wrapper for the pre-bruteforce anonymous probe."""
        return await check_anonymous_access(host, port, service, self.timeout)

    async def _try_default(self, host: str, port: int, service: str, user: str, password: str) -> bool:
        try:
            if service == 'ftp':
                return await self.ftp.try_login(host, port, user, password)
            elif service == 'ssh':
                return await self.ssh.try_login(host, port, user, password)
            elif service == 'mysql':
                return await self.mysql.try_login(host, port, user, password)
            elif service == 'postgresql':
                return await self.postgres.try_login(host, port, user, password)
            elif service == 'mssql':
                return await self.mssql.try_login(host, port, user, password)
            elif service == 'redis':
                return await self.redis_b.try_auth(host, port, password)
            elif service == 'telnet':
                return await self._try_telnet_login(host, port, user, password)
            elif service == 'smtp':
                return await self.smtp_b.try_login(host, port, user, password)
            elif service == 'pop3':
                return await self.pop3_b.try_login(host, port, user, password)
            elif service == 'imap':
                return await self.imap_b.try_login(host, port, user, password)
            elif service == 'smb':
                # SMB guest probe doubles as a credential check
                try:
                    smb = SMBEnumerator(self.timeout)
                    return await smb.check_guest_access(host, port)
                except Exception:
                    return False
        except Exception as e:
            self.logger.debug("Default cred check failed for %s %s@%s: %s", service, user, host, e)
        return False

    async def _try_telnet_login(self, host: str, port: int, user: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(None, lambda: _create_connection(host, port, self.timeout))
        if not sock:
            return False
        try:
            _recv_all(sock, 4096, 5)
            sock.sendall(f'{user}\r\n'.encode())
            _recv_all(sock, 4096, 5)
            sock.sendall(f'{password}\r\n'.encode())
            resp = _recv_all(sock, 4096, 5)
            if resp:
                data = resp.decode('utf-8', errors='ignore')
                return ('incorrect' not in data.lower() and
                        ('invalid' not in data.lower() and
                         ('$' in data or '>' in data or '#' in data or 'login:' in data.lower())))
            return False
        except Exception:
            return False
        finally:
            sock.close()


def _create_connection(host: str, port: int, timeout: int) -> Optional[socket.socket]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock
    except Exception:
        return None


def _recv_all(sock: socket.socket, size: int, timeout: int) -> Optional[bytes]:
    try:
        sock.settimeout(timeout)
        return sock.recv(size)
    except Exception:
        return None


def _build_netbios_session_request() -> bytes:
    return b'\x00\x00\x00\x00\x20\x02\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x46\x45\x4e\x48\x41\x44\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'


def _build_smb_negotiate() -> bytes:
    return (
        b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x41\x00\x01\x00\x02\x02\x00\x00'
    )


def _build_smb_session_setup(username: str, password: str) -> bytes:
    unstructured = username.encode('utf-16le') + b'\x00'
    pwd_unicode = password.encode('utf-16le') + b'\x00' if password else b'\x00\x00'
    body = (
        b'\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x08\x01'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x0c\x00' + struct.pack('<H', len(pwd_unicode)) +
        b'\x00\x00\x00\x00' +
        b'\x0c\x00' + struct.pack('<H', len(unstructured)) +
        unstructured +
        pwd_unicode
    )
    return struct.pack('>I', len(body)) + body


def _parse_smb_dialect(data: bytes) -> Optional[str]:
    if len(data) < 68:
        return None
    dialect_idx = struct.unpack_from('<H', data, 66)[0]
    dialects = {0: 'PC NETWORK PROGRAM 1.0', 2: 'LANMAN1.0', 3: 'LANMAN2.1', 7: 'NT LM 0.12', 0x0202: 'SMB 2.0', 0x0210: 'SMB 2.1', 0x0300: 'SMB 3.0', 0x0302: 'SMB 3.0.2', 0x0311: 'SMB 3.1.1'}
    return dialects.get(dialect_idx, f'Unknown (0x{dialect_idx:04x})')


def _parse_smb_os(data: bytes) -> Optional[str]:
    if len(data) < 100:
        return None
    try:
        os_str = data[100:].split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
        return os_str if os_str else None
    except Exception:
        return None


def _build_snmp_get_request(community: str, oid: str) -> bytes:
    oid_parts = [int(x) for x in oid.split('.')]
    oid_bytes = b'\x06' + bytes([len(oid_parts)])
    for part in oid_parts:
        if part < 128:
            oid_bytes += bytes([part])
        else:
            oid_bytes += bytes([0x80 | (part >> 7), part & 0x7f])
    community_bytes = community.encode()
    pkt = (
        b'\x30' + bytes([len(community_bytes) + 8 + len(oid_bytes) + 4]) +
        b'\x02\x01\x00' +
        b'\x04' + bytes([len(community_bytes)]) + community_bytes +
        b'\xa0' + bytes([len(oid_bytes) + 6]) +
        b'\x02\x01\x00' +
        b'\x02\x01\x00' +
        b'\x30' + bytes([len(oid_bytes) + 2]) +
        oid_bytes +
        b'\x05\x00'
    )
    return pkt


def _parse_snmp_response(data: bytes) -> Optional[str]:
    if len(data) < 20:
        return None
    try:
        idx = data.find(b'\x04')
        if idx > 0 and idx + 1 < len(data):
            strlen = data[idx + 1]
            str_data = data[idx + 2:idx + 2 + strlen]
            return str_data.decode('utf-8', errors='ignore')
        idx = data.find(b'\x02')
        if idx > 0 and idx + 1 < len(data):
            intlen = data[idx + 1]
            intval = int.from_bytes(data[idx + 2:idx + 2 + intlen], 'big')
            return str(intval)
    except Exception:
        pass
    return None


def _build_mysql_auth(handshake: bytes, username: str, password: str) -> bytes:
    if len(handshake) < 36:
        return b''
    auth_data_1 = handshake[8:16]
    if len(handshake) > 36:
        auth_data_2_len = handshake[36]
        auth_data_2 = handshake[37:37 + auth_data_2_len] if auth_data_2_len > 0 else b''
    else:
        auth_data_2 = b''
    scramble = auth_data_1 + auth_data_2[:12]
    hash_result = _mysql_native_password(password.encode(), scramble)
    flags = 0x0085
    charset = 33
    user_bytes = username.encode()
    auth_len = len(hash_result)
    pkt_len = 4 + 4 + user_bytes.count(True) + 1 + 1 + 4 + 4 + 4 + len(scramble) + auth_len + 1 + 1 + 1 + 1 + 2 + 4 + 4 + 4
    pkt_len = 4 + 4 + len(user_bytes) + 1 + len(scramble) + len(hash_result)

    def _int_lenenc(val):
        if val < 251: return bytes([val])
        elif val < 65536: return b'\xfc' + struct.pack('<H', val)
        elif val < 16777216: return b'\xfd' + struct.pack('<I', val)[:3]
        else: return b'\xfe' + struct.pack('<Q', val)

    cap = struct.pack('<I', 0x80a85)
    max_pkt = struct.pack('<I', 16777215)
    charset_b = bytes([charset])
    pkt = b'\x00\x00\x01' + cap + max_pkt + charset_b + b'\x00' * 23 + user_bytes.encode() + b'\x00'
    pkt += _int_lenenv(len(scramble)) + scramble
    if hash_result:
        pkt += hash_result
    full_pkt = struct.pack('<I', len(pkt))[:3] + b'\x00' + pkt[3:]
    return full_pkt


def _int_lenenc(val): return bytes([val]) if val < 251 else (b'\xfc' + struct.pack('<H', val)) if val < 65536 else (b'\xfd' + struct.pack('<I', val)[:3])


def _int_lenenv(val):
    return b'\xfb' if val is None or val == (None) else bytes([val]) if val < 251 else b'\xfc' + struct.pack('<H', val) if val < 65536 else b'\xfd' + struct.pack('<I', val)[:3]


def _mysql_native_password(password: bytes, scramble: bytes) -> bytes:
    if not password:
        return b''
    sha1 = hashlib.sha1
    h1 = sha1(password).digest()
    h2 = sha1(h1).digest()
    h3 = sha1(scramble + h2).digest()
    return bytes(a ^ b for a, b in zip(h1, h3))


def _build_pg_startup(user: str, db: str) -> bytes:
    params = b'user\x00' + user.encode() + b'\x00database\x00' + db.encode() + b'\x00\x00'
    pkt = struct.pack('!I', 196608) + params
    return struct.pack('!I', len(pkt) + 4) + pkt


def _build_pg_password(salt: bytes, password: str) -> bytes:
    if not password:
        empty = b''
        return struct.pack('!I', 4 + len(empty)) + b'p' + empty
    # PostgreSQL's protocol REQUIRES MD5 here (md5 response format); this is
    # protocol compliance, not a security decision - usedforsecurity=False
    # marks it as such (bandit B324).
    md5_hash = hashlib.md5(password.encode() + salt[:4],
                           usedforsecurity=False).hexdigest().encode()
    md5_resp = b'md5' + md5_hash
    return struct.pack('!I', 4 + len(md5_resp)) + b'p' + md5_resp


def _build_mssql_prelogin() -> bytes:
    pkt = b'\x12\x01\x00\x2f\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    return struct.pack('>I', len(pkt))[:2] + struct.pack('>H', len(pkt)) + pkt[4:]


def _build_mssql_login(username: str, password: str) -> bytes:
    uname_unicode = username.encode('utf-16le')
    pwd_unicode = password.encode('utf-16le')
    host_unicode = b'localhost\x00\x00'.encode('utf-16le') if False else b'l\x00o\x00c\x00a\x00l\x00h\x00o\x00s\x00t\x00'
    host_unicode = 'localhost'.encode('utf-16le') + b'\x00\x00'
    app_unicode = b'a\x00t\x00h\x00e\x00n\x00a\x00\x00\x00'
    srv_unicode = b'\x00\x00'
    lib_unicode = b'\x00\x00'
    pkt = b'\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    pkt += struct.pack('<I', len(uname_unicode))
    pkt += struct.pack('<I', 0)
    pkt += struct.pack('<I', len(pwd_unicode))
    pkt += struct.pack('<I', 0)
    pkt += struct.pack('<I', len(host_unicode))
    pkt += struct.pack('<I', 0)
    pkt += struct.pack('<I', len(app_unicode))
    pkt += struct.pack('<I', 0)
    pkt += struct.pack('<I', len(srv_unicode))
    pkt += struct.pack('<I', 0)
    pkt += struct.pack('<I', len(lib_unicode))
    pkt += struct.pack('<I', 0)
    pkt += b'\x00\x00\x00\x00\x00\x00\x00\x00'
    pkt += pwd_unicode
    pkt += uname_unicode
    pkt += host_unicode
    pkt += app_unicode
    pkt += srv_unicode
    pkt += lib_unicode
    header = struct.pack('>I', len(pkt) + 8)[:2] + struct.pack('>H', len(pkt) + 8)
    header += b'\x00\x00\x00\x00'
    return header + pkt
