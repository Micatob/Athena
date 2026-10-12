"""Console colors: plain when piped, colored on a TTY, off with NO_COLOR."""
import sys

import pytest

from modules import console


class _Tty:
    def isatty(self):
        return True

    def write(self, s):
        pass

    def flush(self):
        pass


@pytest.fixture
def restore():
    yield
    console.enable()


def test_paint_plain_when_not_tty(restore):
    # Under pytest stdout is captured (not a TTY) -> no ANSI emitted.
    assert console.paint('[+] Port 21 open (FTP)') == '[+] Port 21 open (FTP)'
    assert console.paint('[!] LOCKOUT on x') == '[!] LOCKOUT on x'


def test_paint_colors_on_tty(monkeypatch, restore):
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr('sys.stdout', _Tty())
    out = console.paint('[+] Port 21 open (FTP)')
    assert '\x1b[' in out
    assert 'Port 21 open' in out


def test_no_color_env_disables(monkeypatch, restore):
    monkeypatch.setenv('NO_COLOR', '1')
    monkeypatch.setattr('sys.stdout', _Tty())
    assert console.paint('[+] hi') == '[+] hi'
    assert console.ok('[+] hi') == '[+] hi'


def test_disable_flag_wins_over_tty(monkeypatch, restore):
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr('sys.stdout', _Tty())
    console.disable()
    assert console.paint('[+] hi') == '[+] hi'
    console.enable()
    assert '\x1b[' in console.paint('[+] hi')


def test_cprint_passthrough_plain(capsys, restore):
    console.cprint('[+] PDF report:', '/tmp/x.html')
    assert capsys.readouterr().out == '[+] PDF report: /tmp/x.html\n'
    console.cprint()
    assert capsys.readouterr().out == '\n'


def test_paint_never_double_colors(monkeypatch, restore):
    monkeypatch.delenv('NO_COLOR', raising=False)
    monkeypatch.setattr('sys.stdout', _Tty())
    once = console.paint('[+] hi')
    assert console.paint(once) == once


def test_phase_runs_without_error(capsys, restore):
    console.phase('PHASE 9: TEST')
    out = capsys.readouterr().out
    assert 'PHASE 9: TEST' in out
