import asyncio
import socket
import time

from aiohttp import web

import modules.bruteforce as bruteforce


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_unreachable_form_is_skipped_instead_of_stalling(capsys):
    async def scenario():
        module = bruteforce.BruteforceModule()
        try:
            forms = [{'url': 'http://127.0.0.1:1/login/', 'method': 'POST',
                      'inputs': [{'name': 'user'}, {'name': 'pass'}]}]
            return await module.intelligent_bruteforce(forms)
        finally:
            await module.close()

    started = time.monotonic()
    result = run(scenario())
    elapsed = time.monotonic() - started

    assert result == []
    assert elapsed < 15, f'should fail fast, took {elapsed:.1f}s'
    assert 'unreachable' in capsys.readouterr().out


def test_progress_is_printed_while_attempts_run(capsys):
    async def scenario():
        async def handler(request):
            return web.Response(text='invalid credentials', status=401)

        module = bruteforce.BruteforceModule()
        port = _free_port()
        app = web.Application()
        app.router.add_route('*', '/login/', handler)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, '127.0.0.1', port).start()
        try:
            module.MAX_ATTEMPTS_PER_FORM = 40
            module.MAX_PARALLEL_ATTEMPTS = 4
            forms = [{'url': f'http://127.0.0.1:{port}/login/', 'method': 'POST',
                      'inputs': [{'name': 'user'}, {'name': 'pass'}]}]
            return await module.intelligent_bruteforce(forms)
        finally:
            await module.close()
            await runner.cleanup()

    result = run(scenario())
    out = capsys.readouterr().out

    assert result == []
    assert 'attempts' in out, f'expected progress output, got:\n{out}'
    assert 'Intelligent bruteforce on' in out


def test_successful_login_is_reported(capsys):
    async def scenario():
        async def handler(request):
            return web.Response(text='<html>dashboard welcome</html>', status=200)

        module = bruteforce.BruteforceModule()
        port = _free_port()
        app = web.Application()
        app.router.add_route('*', '/login/', handler)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, '127.0.0.1', port).start()
        try:
            forms = [{'url': f'http://127.0.0.1:{port}/login/', 'method': 'POST',
                      'inputs': [{'name': 'user'}, {'name': 'pass'}]}]
            return await module.intelligent_bruteforce(forms)
        finally:
            await module.close()
            await runner.cleanup()

    result = run(scenario())
    out = capsys.readouterr().out

    assert len(result) == 1
    assert result[0]['username'] in ('admin', 'root', 'administrator')
    assert 'SUCCESS' in out


def test_deadline_bounds_a_slow_target():
    async def scenario():
        module = bruteforce.BruteforceModule()
        try:
            module.FORM_DEADLINE_SECONDS = 0.0
            return await module._run_attempts(
                'http://127.0.0.1:1/login/', 'POST', 'user', 'pass',
                [('admin', 'admin'), ('root', 'root')], {})
        finally:
            await module.close()

    started = time.monotonic()
    assert run(scenario()) is None
    assert time.monotonic() - started < 5
