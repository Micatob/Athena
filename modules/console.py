"""Terminal colors for Athena console output.

Windows-safe via colorama (wraps stdout so ANSI works in conhost and
PowerShell).  Colors apply ONLY when stdout is a real terminal — piped
output (``> fullscan.txt``), pytest capture, ``--no-color`` and the
``NO_COLOR`` env var all stay plain text.
"""
import os
import re
import sys

try:
    import colorama
    colorama.init()
except Exception:  # pragma: no cover - raw ANSI still works on modern terms
    pass

_RESET = '\x1b[0m'
_BOLD = '\x1b[1m'
_DIM = '\x1b[2m'
_RED = '\x1b[31m'
_GREEN = '\x1b[32m'
_YELLOW = '\x1b[33m'
_MAGENTA = '\x1b[35m'
_CYAN = '\x1b[36m'
_BRIGHT_RED = '\x1b[91m'
_BRIGHT_GREEN = '\x1b[92m'
_BRIGHT_CYAN = '\x1b[96m'

_disabled = False


def disable() -> None:
    """Turn colors off (``--no-color``)."""
    global _disabled
    _disabled = True


def enable() -> None:
    """Turn colors back on."""
    global _disabled
    _disabled = False


def enabled(file=None) -> bool:
    """Colors only on a real terminal, never in pipes/files/tests."""
    if _disabled:
        return False
    if os.environ.get('NO_COLOR'):
        return False
    try:
        stream = file if file is not None else sys.stdout
        return bool(stream.isatty())
    except Exception:
        return False


_MARKER_COLORS = {
    '[+]': _GREEN,
    '[!]': _BRIGHT_RED,
    '[*]': _CYAN,
    '[-]': _DIM,
    '[time]': _MAGENTA,
    '[Athena]': _BRIGHT_CYAN,
}
_MARKER_RE = re.compile(r'\[\+\]|\[\!\]|\[\*\]|\[-\]|\[time\]|\[Athena\]')
_BAD_RE = re.compile(
    r'\b(LOCKOUT|ANONYMOUS|LOCKED|BLOCKED|CRITICAL|FAILED|DENIED)\b')
_GOOD_RE = re.compile(r'\b(SUCCESS|CONFIRMED|VERIFIED)\b')
_CVE_RE = re.compile(r'\bCVE-\d{4}-\d+\b')


def _wrap(text: str, code: str) -> str:
    if not enabled():
        return text
    return f'{code}{text}{_RESET}'


def paint(text: str, file=None) -> str:
    """Color Athena's ``[+]``/``[!]``/``[*]`` markers, status keywords and
    CVE ids.  Plain text (or already-colored text) passes through untouched.
    """
    if not enabled(file) or '\x1b' in text:
        return text

    def _marker(m: 're.Match') -> str:
        token = m.group(0)
        return f"{_MARKER_COLORS[token]}{token}{_RESET}"

    def _bad(m: 're.Match') -> str:
        return f"{_BOLD}{_BRIGHT_RED}{m.group(0)}{_RESET}"

    def _good(m: 're.Match') -> str:
        return f"{_BOLD}{_BRIGHT_GREEN}{m.group(0)}{_RESET}"

    def _cve(m: 're.Match') -> str:
        return f"{_YELLOW}{m.group(0)}{_RESET}"

    text = _MARKER_RE.sub(_marker, text)
    text = _BAD_RE.sub(_bad, text)
    text = _GOOD_RE.sub(_good, text)
    text = _CVE_RE.sub(_cve, text)
    return text


def cprint(*args, sep: str = ' ', end: str = '\n', **kwargs) -> None:
    """Drop-in ``print`` replacement that paints Athena markers.

    Accepts the same call shapes as ``print`` (``sep``/``end``/``file``/
    ``flush`` pass through); only the text content is painted.
    """
    _file = kwargs.get('file', None)
    print(paint(sep.join(str(a) for a in args), file=_file), end=end, **kwargs)


def phase(title: str) -> None:
    """Cyan ``===`` banner for scan phase headers."""
    bar = '=' * 60
    body = f'\n{bar}\n  {title}\n{bar}\n'
    print(_wrap(body, _CYAN + _BOLD) if enabled() else body)


def ok(text: str) -> str:
    """Green string (safe to pass to plain ``print`` or ``cprint``)."""
    return _wrap(text, _GREEN)


def good(text: str) -> str:
    """Bright-bold green string for verified wins."""
    return _wrap(text, _BRIGHT_GREEN + _BOLD)


def warn(text: str) -> str:
    """Yellow string."""
    return _wrap(text, _YELLOW)


def bad(text: str) -> str:
    """Bright-bold red string."""
    return _wrap(text, _BRIGHT_RED + _BOLD)


def info(text: str) -> str:
    """Cyan string."""
    return _wrap(text, _CYAN)


def dim(text: str) -> str:
    """Dim string."""
    return _wrap(text, _DIM)
