"""Regression tests for review #9 fixes."""

from __future__ import annotations

import json

import pytest

from argus.scanners import static_python
from argus.scanners import supply_chain


@pytest.fixture()
def static_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


# ---------------------------------------------------------------------------
# Static analysis: new sinks
# ---------------------------------------------------------------------------

def test_static_detects_subprocess_getoutput(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import subprocess\nsubprocess.getoutput('echo hi')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.subprocess_getoutput" in rids


def test_static_detects_subprocess_getstatusoutput(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import subprocess\nsubprocess.getstatusoutput('echo hi')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.subprocess_getstatusoutput" in rids


def test_static_detects_os_popen(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("import os\nos.popen('echo hi')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.os_popen" in rids


def test_static_detects_direct_hashlib_md5(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.weak_hash_md5_direct" in rids


def test_static_detects_direct_hashlib_sha1(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.weak_hash_sha1_direct" in rids


def test_static_detects_query_fstring_as_sql(vault, static_scope):
    """SQLAlchemy / Databases idiom: `session.query(f"...")`."""
    proj, token = static_scope
    (proj / "a.py").write_text(
        "def go(session, x):\n    session.query(f'SELECT * FROM t WHERE id={x}')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


# ---------------------------------------------------------------------------
# Supply chain: npm wildcard + "latest" are unpinned
# ---------------------------------------------------------------------------

@pytest.fixture()
def supply_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["supply_chain"])
    return proj, token


def test_supply_flags_npm_wildcard_star(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "dependencies": {"react": "*"},
    }))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.npm.unpinned" in rids


def test_supply_flags_npm_latest_tag(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "dependencies": {"react": "latest"},
    }))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.npm.unpinned" in rids


def test_supply_pinned_npm_still_passes(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "dependencies": {"react": "18.2.0"},
    }))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.npm.unpinned" not in rids
