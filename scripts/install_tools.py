"""Install Athena's optional external engines (GitHub-safe).

Nothing is committed to the repo: this script downloads official release
archives at install time into a per-user tools dir that
``modules.tool_bridge.find_binary`` already searches::

    Windows: %LOCALAPPDATA%\\Programs\\athena-tools
    Linux:   ~/.local/bin

Covers: nuclei, dalfox, ProjectDiscovery httpx, sqlmap (+ pip wafw00f).
Missing tools are not fatal: Athena degrades to ``unavailable`` and the
native scanners still run. Run with ``--verify-only`` on a fresh machine
to see what is missing.

Usage:
    python scripts/install-tools.py
    python scripts/install-tools.py --verify-only
    python scripts/install-tools.py --only httpx dalfox --dest <dir>
"""
import argparse
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

REPO = "Micatob/Athena"

PINNED = {
    # Known-good versions seen on the maintainer's box (Oct 2026).
    # httpx/nuclei float to latest unless --pinned is given.
    "nuclei": "3.11.1",
    "dalfox": "3.2.4",
}

RELEASES = {
    "nuclei": "projectdiscovery/nuclei",
    "dalfox": "hahwul/dalfox",
    "httpx": "projectdiscovery/httpx",
    "sqlmap": "sqlmapproject/sqlmap",
}


def tools_dir(dest=None):
    if dest:
        return os.path.abspath(os.path.expandvars(dest))
    if os.name == "nt":
        base = os.path.expandvars(r"%LOCALAPPDATA%\Programs\athena-tools")
        if "%LOCALAPPDATA%" in base:
            base = os.path.join(os.path.expanduser("~"), "athena-tools")
        return base
    return os.path.join(os.path.expanduser("~"), ".local", "bin")


def _is_windows():
    return os.name == "nt" or platform.system().lower() == "windows"


def _github_latest_tag(repo):
    """Resolve latest release tag via redirect; None on offline."""
    url = "https://github.com/%s/releases/latest" % repo
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Athena-installer"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            final = resp.geturl()
        tag = final.rstrip("/").rsplit("/", 1)[-1]
        return tag or None
    except Exception as exc:
        print("  [!] latest-tag lookup failed for %s: %s" % (repo, exc))
        return None


def _download(url, dest_path):
    req = urllib.request.Request(url, headers={"User-Agent": "Athena-installer"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest_path, "wb") as fh:
        shutil.copyfileobj(resp, fh, length=1024 * 64)
    return dest_path


def _asset_urls(tool, tag):
    """(urls, binary_name) for a tool at a release tag."""
    ver = tag.lstrip("v")
    win = _is_windows()
    if tool == "nuclei":
        if win:
            return (["https://github.com/projectdiscovery/nuclei/releases/download/%s/nuclei_%s_windows_amd64.zip" % (tag, ver)], "nuclei.exe")
        return (["https://github.com/projectdiscovery/nuclei/releases/download/%s/nuclei_%s_linux_amd64.zip" % (tag, ver)], "nuclei")
    if tool == "dalfox":
        if win:
            return (["https://github.com/hahwul/dalfox/releases/download/%s/dalfox_%s_windows_amd64.zip" % (tag, ver)], "dalfox.exe")
        return (["https://github.com/hahwul/dalfox/releases/download/%s/dalfox_%s_linux_amd64.tar.gz" % (tag, ver)], "dalfox")
    if tool == "httpx":
        if win:
            return (["https://github.com/projectdiscovery/httpx/releases/download/%s/httpx_%s_windows_amd64.zip" % (tag, ver)], "httpx.exe")
        return (["https://github.com/projectdiscovery/httpx/releases/download/%s/httpx_%s_linux_amd64.zip" % (tag, ver)], "httpx")
    if tool == "sqlmap":
        return (["https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip"], "sqlmap.py")
    return ([], "")


def _extract_binary(archive, binary_name, dest_dir):
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            # sqlmap ships as a source tree (sqlmap-master/...), not a
            # single binary: extract the whole tree first.  The generic
            # single-file scan below would otherwise grab only the
            # sqlmap.py launcher and leave a broken install behind.
            if binary_name == "sqlmap.py":
                tmp = tempfile.mkdtemp(prefix="athena-sqlmap-")
                zf.extractall(tmp)
                return tmp
            for member in zf.namelist():
                base = os.path.basename(member.rstrip("/"))
                if base.lower() == binary_name.lower():
                    data = zf.read(member)
                    out = os.path.join(dest_dir, binary_name)
                    with open(out, "wb") as fh:
                        fh.write(data)
                    return out
    elif archive.endswith(".tar.gz"):
        import tarfile
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                if os.path.basename(member.name) == binary_name:
                    tf.extract(member, dest_dir)
                    return os.path.join(dest_dir, member.name)
    return None


def _make_executable(path):
    try:
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def _run_version(binary, args=("--version",)):
    try:
        proc = subprocess.run([binary, args[0]], capture_output=True, text=True, timeout=20)
        blob = (proc.stdout or "") + (proc.stderr or "")
        return blob.strip().splitlines()[0][:120] if blob.strip() else "ok"
    except Exception as exc:
        return "unverified: %s" % exc


def install_tool(tool, dest_dir, pinned=False):
    os.makedirs(dest_dir, exist_ok=True)
    if tool == "wafw00f":
        print("[*] wafw00f: pip install ...")
        proc = subprocess.run([sys.executable, "-m", "pip", "install", "-q", "wafw00f"],
                              capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            print("  [!] pip install wafw00f failed:\n%s" % (proc.stderr or proc.stdout))
            return False
        print("  [+] wafw00f installed via pip")
        return True
    repo = RELEASES[tool]
    tag = ("v%s" % PINNED[tool] if tool in PINNED else None) if pinned else _github_latest_tag(repo)
    if not tag:
        if tool in PINNED:
            tag = "v%s" % PINNED[tool]
            print("  [*] %s: offline, falling back to pinned %s" % (tool, tag))
        else:
            print("  [!] %s: cannot resolve latest release (offline?)" % tool)
            return False
    urls, binary = _asset_urls(tool, tag)
    print("[*] %s %s ..." % (tool, tag))
    tmp = tempfile.mkdtemp(prefix="athena-tool-")
    ok = False
    for url in urls:
        arc = os.path.join(tmp, url.rsplit("/", 1)[-1])
        try:
            print("    downloading %s" % url)
            _download(url, arc)
        except Exception as exc:
            print("    [!] download failed: %s" % exc)
            continue
        got = _extract_binary(arc, binary, dest_dir)
        if got is None:
            print("    [!] %s not found in archive" % binary)
            continue
        if tool == "sqlmap":
            # got is the extracted tree; move sqlmap-master -> <dest>/sqlmap
            import glob
            cands = glob.glob(os.path.join(got, "sqlmap-master*")) or glob.glob(os.path.join(got, "*sqlmap*"))
            src = cands[0] if cands else got
            target = os.path.join(dest_dir, "sqlmap")
            # A previous broken install may have left a FILE named `sqlmap`
            # (single launcher grabbed instead of the tree) where the
            # directory must go - remove either form before moving.
            try:
                if os.path.isdir(target) and not os.path.islink(target):
                    shutil.rmtree(target, ignore_errors=True)
                elif os.path.lexists(target):
                    os.remove(target)
            except Exception as exc:
                print("    [!] cannot clear stale %s: %s" % (target, exc))
                continue
            try:
                shutil.move(src, target)
            except Exception as exc:
                print("    [!] cannot place sqlmap tree: %s" % exc)
                continue
            entry = os.path.join(target, "sqlmap.py")
            if not os.path.isfile(entry):
                print("    [!] sqlmap tree has no sqlmap.py entry point - install FAILED")
                continue
            if _is_windows():
                with open(os.path.join(dest_dir, "sqlmap.cmd"), "w") as fh:
                    fh.write('@echo off\r\npython "%s" %%*\r\n' % entry)
            else:
                with open(os.path.join(dest_dir, "sqlmap"), "w") as fh:
                    fh.write('#!/bin/sh\nexec python3 "%s" "$@"\n' % entry)
                _make_executable(os.path.join(dest_dir, "sqlmap"))
            print("  [+] sqlmap tree at %s" % target)
            ok = True
            break
        _make_executable(got)
        print("  [+] %s -> %s (%s)" % (tool, got, _run_version(got, ("-version",))))
        ok = True
        break
    shutil.rmtree(tmp, ignore_errors=True)
    return ok


def verify(dest_dir):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    try:
        from modules.tool_bridge import find_binary
    except Exception as exc:
        print("[!] cannot import tool_bridge: %s" % exc)
        return False
    print("tools dir: %s" % dest_dir)
    all_ok = True
    for tool in ("nuclei", "sqlmap", "dalfox", "wafw00f", "httpx"):
        path = find_binary(tool)
        # find_binary does not know dest_dir unless it is on PATH/_EXTRA_SEARCH_DIRS;
        # also probe dest_dir directly so a fresh install verifies immediately.
        if not path:
            for suffix in (".exe", ".cmd", "") if _is_windows() else ("",):
                cand = os.path.join(dest_dir, tool + suffix)
                if os.path.isfile(cand):
                    path = cand
                    break
        if tool == "sqlmap":
            # A file named `sqlmap` is NOT an install - the tree entry
            # point must exist (a past bug left exactly such a stray file).
            entry = os.path.join(dest_dir, "sqlmap", "sqlmap.py")
            if not os.path.isfile(entry):
                print("  %-8s BROKEN (no sqlmap/sqlmap.py - re-run install)" % tool)
                all_ok = False
                continue
            print("  %-8s %s" % (tool, entry))
            continue
        print("  %-8s %s" % (tool, path or "MISSING"))
        if not path and tool not in ("sqlmap", "httpx"):
            all_ok = False
    print("\nRun `python athena.py --list-tools` for version detail.")
    return all_ok


def main(argv=None):
    ap = argparse.ArgumentParser(description="Install Athena optional engines (downloads official releases).")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--only", nargs="*", default=["nuclei", "dalfox", "httpx", "sqlmap", "wafw00f"])
    ap.add_argument("--dest", default=None)
    ap.add_argument("--pinned", action="store_true", help="use pinned versions instead of latest")
    args = ap.parse_args(argv)
    dest = tools_dir(args.dest)
    if args.verify_only:
        ok = verify(dest)
        return 0 if ok else 1
    print("Installing to %s" % dest)
    results = {}
    for tool in args.only:
        if tool not in RELEASES and tool != "wafw00f":
            print("[!] unknown tool: %s" % tool)
            results[tool] = False
            continue
        try:
            results[tool] = install_tool(tool, dest, pinned=args.pinned)
        except Exception as exc:
            print("  [!] %s failed: %s" % (tool, exc))
            results[tool] = False
    print("\n==== summary ====")
    for tool, ok in results.items():
        print("  %-8s %s" % (tool, "OK" if ok else "FAILED"))
    verify(dest)
    if _is_windows():
        print("\nNOTE: open a NEW terminal so PATH picks up %s" % dest)
        print("Repo: https://github.com/%s" % REPO)
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
