"""Local smoke test: WAF detection + tamper bypass + credential stuffing."""

import asyncio
import os
import sys
import tempfile
from aiohttp import web

from modules.waf import WAFDetector
from modules.bruteforce import BruteforceModule

PORT = 8699


async def handler(request: web.Request) -> web.Response:
    path = request.path
    if path == '/login':
        data = dict(request.query)
        if data.get('username') == 'admin' and data.get('password') == 's3cret!':
            return web.Response(text='Welcome back, admin! Dashboard active', headers={'server': 'nginx'})
        return web.Response(text='Invalid login credentials. Please try again.', status=401,
                            headers={'server': 'nginx'})
    if path == '/admin':
        return web.Response(text='Admin panel content here', headers={'server': 'cloudflare', 'cf-ray': 'smoke123'})
    # "WAF" challenge probing: obvious attack payloads get 403, benign = 200
    if any(k in request.query for k in ('id', 'q', 'cmd', 'file')):
        for v in request.query.values():
            if 'OR' in v.upper() and "'" in v:
                # allow tampered variant with comment injection, block raw
                if '/**/' not in v:
                    return web.Response(text='413 Request Entity Too Large', status=403,
                                        headers={'server': 'cloudflare'})
            if 'script' in v.lower() or 'alert' in v.lower():
                return web.Response(text='access denied', status=403, headers={'server': 'cloudflare'})
            if 'passwd' in v:
                return web.Response(text='Request blocked by security policy', status=403,
                                    headers={'server': 'cloudflare'})
            if 'etc' in v:
                return web.Response(text='verification required', status=403, headers={'server': 'cloudflare'})
    return web.Response(text='hello world', headers={'server': 'nginx'})


async def main() -> int:
    app = web.Application()
    app.router.add_get('/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', PORT)
    await site.start()
    base = f'http://127.0.0.1:{PORT}'
    ok = True

    print('=== 1. WAF detection ===')
    detector = WAFDetector()
    report = await detector.detect(base + '/admin')
    await detector.close()
    print(f'  detected={report.detected} waf={report.waf_name} conf={report.confidence:.2f} '
          f'blocked={report.challenge_blocked}')
    if not report.detected or report.waf_name != 'Cloudflare':
        print('  FAIL: Cloudflare not detected'); ok = False

    print('=== 2. Tamper bypass (raw payload blocked, variant passes) ===')
    raw = "' OR 1=1--"
    variants = WAFDetector.tamper(raw, 'sql', limit=2)
    print(f'  raw payload  -> HTTP {await aiohttp_client_get(base, "?id=" + raw.replace(" ", "%20"))}')
    for v in variants:
        print(f'  tampered "{v}" -> HTTP {await aiohttp_client_get(base, "?id=" + v.replace(" ", "%20"))}')

    print('=== 3. Credential stuffing ===')
    form = {'url': base + '/login', 'method': 'GET',
            'inputs': [{'name': 'username'}, {'name': 'password'}]}
    creds_path = os.path.join(tempfile.gettempdir(), 'smoke_creds.txt')
    with open(creds_path, 'w') as f:
        f.write('admin:admin\nadmin:s3cret!\n')
    bf = BruteforceModule()
    results = await bf.credential_stuffing([form], creds_file=creds_path)
    await bf.close()
    os.unlink(creds_path)
    for r in results:
        print(f'  [+] {r["username"]}:{r["password"]}')
    if not results or results[0]['password'] != 's3cret!':
        print('  FAIL: stuffing did not find admin:s3cret!')
        ok = False

    await runner.cleanup()
    print('SMOKE', 'PASSED' if ok else 'FAILED')
    return 0 if ok else 1


async def aiohttp_client_get(base, raw):
    import aiohttp
    async with aiohttp.ClientSession() as s:
        async with s.get(base + raw) as r:
            return r.status


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))