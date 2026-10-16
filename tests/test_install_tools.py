"""Installer: offline unit tests (no network)."""
import os

import scripts.install_tools as inst


def test_tools_dir_override():
    assert inst.tools_dir('/tmp/athena-x') == os.path.abspath('/tmp/athena-x')


def test_tools_dir_default_is_per_user():
    d = inst.tools_dir(None)
    assert d and '%LOCALAPPDATA%' not in d
    assert 'athena-tools' in d or '.local' in d


def test_asset_urls_windows_names():
    urls, binary = inst._asset_urls('dalfox', 'v3.2.4')
    assert binary == ('dalfox.exe' if inst._is_windows() else 'dalfox')
    assert urls and 'dalfox' in urls[0]


def test_asset_urls_httpx():
    urls, binary = inst._asset_urls('httpx', 'v1.7.1')
    assert 'httpx' in binary and urls


def test_verify_reports_missing_without_network(tmp_path, monkeypatch, capsys):
    import modules.tool_bridge as tb
    monkeypatch.setattr(tb, 'find_binary', lambda name, extra_dirs=(): None)
    # verify() imports tool_bridge itself; patch its find_binary too
    import scripts.install_tools as inst2
    monkeypatch.setattr('modules.tool_bridge.find_binary', lambda name, extra_dirs=(): None)
    ok = inst2.verify(str(tmp_path))
    assert ok is False
    assert 'MISSING' in capsys.readouterr().out


def test_extract_sqlmap_takes_tree_not_single_file(tmp_path):
    """Regression: the single-file scan grabbed only the sqlmap.py launcher,
    leaving a FILE named `sqlmap` and a shim to nowhere."""
    import zipfile
    archive = str(tmp_path / "master.zip")
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("sqlmap-master/sqlmap.py", "# launcher")
        zf.writestr("sqlmap-master/lib/core.py", "# lib")
    out = inst._extract_binary(archive, "sqlmap.py", str(tmp_path))
    assert os.path.isdir(out)
    assert os.path.isfile(os.path.join(out, "sqlmap-master", "sqlmap.py"))


def test_verify_rejects_stray_sqlmap_file(tmp_path, capsys):
    (tmp_path / "sqlmap").write_text("# stray launcher, not a tree")
    assert inst.verify(str(tmp_path)) is False
    assert "BROKEN" in capsys.readouterr().out


def test_verify_accepts_sqlmap_tree(tmp_path, monkeypatch, capsys):
    tree = tmp_path / "sqlmap"
    tree.mkdir()
    (tree / "sqlmap.py").write_text("# entry point")
    import modules.tool_bridge as tb
    monkeypatch.setattr(tb, "find_binary", lambda name, extra_dirs=(): None)
    inst.verify(str(tmp_path))
    out = capsys.readouterr().out
    assert "BROKEN" not in out
    assert "sqlmap.py" in out
