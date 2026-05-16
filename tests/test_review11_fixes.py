"""Regression tests for review #11 fixes (final pluginpool-wide review)."""

from __future__ import annotations

import pytest

from argus.scanners import static_python


@pytest.fixture()
def static_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


def test_executemany_fstring_is_flagged(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "def go(cursor, rows, table):\n"
        "    cursor.executemany(f'INSERT INTO {table} VALUES (?)', rows)\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


def test_yaml_load_with_safeloader_keyword_is_silent(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import yaml\nyaml.load(open('x.yml'), Loader=yaml.SafeLoader)\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.yaml_load" not in rids


def test_yaml_load_with_safeloader_positional_is_silent(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import yaml\nyaml.load(open('x.yml'), yaml.SafeLoader)\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.yaml_load" not in rids


def test_yaml_load_without_loader_still_flagged(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import yaml\nyaml.load(open('x.yml'))\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.yaml_load" in rids


def test_unrelated_loads_method_is_not_flagged(vault, static_scope):
    """``my_codec.loads(...)`` is not pickle."""
    proj, token = static_scope
    (proj / "a.py").write_text(
        "class Codec:\n    def loads(self, x): return x\n"
        "def go(codec, data):\n    codec.loads(data)\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.pickle_loads" not in rids


def test_unrelated_system_method_is_not_flagged(vault, static_scope):
    """``logger.system(...)`` is not ``os.system``."""
    proj, token = static_scope
    (proj / "a.py").write_text(
        "class Logger:\n    def system(self, msg): print(msg)\n"
        "Logger().system('hi')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.os_system" not in rids


def test_real_pickle_loads_still_flagged(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("import pickle\npickle.loads(b'x')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.pickle_loads" in rids
