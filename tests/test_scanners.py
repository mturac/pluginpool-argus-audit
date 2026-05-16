"""Tests for static, secrets, supply-chain scanners."""

from __future__ import annotations

import json
import textwrap

import pytest

from argus.errors import ScopeViolation
from argus.scanners import secrets as secrets_scanner
from argus.scanners import static_python
from argus.scanners import supply_chain


@pytest.fixture()
def static_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


def test_static_refuses_without_static_read_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["http:passive"])
    with pytest.raises(ScopeViolation):
        static_python.scan(vault, token, str(proj))


def test_static_detects_pickle_loads(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("import pickle\npickle.loads(b'data')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.pickle_loads" in rids


def test_static_detects_subprocess_shell_true(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("import subprocess\nsubprocess.run('ls', shell=True)\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.subprocess_shell_true" in rids


def test_static_detects_sql_fstring(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("def q(c,x):\n    c.execute(f'SELECT * FROM t WHERE id={x}')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


def test_static_detects_weak_hash(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("import hashlib\nhashlib.new('md5')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.weak_hash_md5" in rids


def test_static_clean_file_yields_no_findings(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("def add(a,b): return a+b\n")
    assert static_python.scan(vault, token, str(proj)) == []


@pytest.fixture()
def secrets_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


def test_secrets_detects_aws_access_key(vault, secrets_scope):
    proj, token = secrets_scope
    (proj / "cfg.py").write_text('AWS = "AKIAABCDEFGHIJKLMNOP"\n')
    rids = {f.rule_id for f in secrets_scanner.scan(vault, token, str(proj))}
    assert "argus.secrets.aws_access_key_id" in rids


def test_secrets_redacts_secret_in_evidence(vault, secrets_scope):
    proj, token = secrets_scope
    secret = "AKIA" + "A" * 16
    (proj / "cfg.py").write_text(f'KEY = "{secret}"\n')
    findings = secrets_scanner.scan(vault, token, str(proj))
    for f in findings:
        assert secret not in f.evidence
        assert f.evidence.startswith("sha256:")


def test_secrets_high_entropy_literal_flagged(vault, secrets_scope):
    proj, token = secrets_scope
    high = "Jf83hG5kLp9MnQ2rT4Wv8XzYbCdEfGhI"
    (proj / "cfg.py").write_text(f'TOK = "{high}"\n')
    rids = {f.rule_id for f in secrets_scanner.scan(vault, token, str(proj))}
    assert "argus.secrets.high_entropy_literal" in rids


@pytest.fixture()
def supply_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["supply_chain"])
    return proj, token


def test_supply_refuses_without_supply_chain_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    with pytest.raises(ScopeViolation):
        supply_chain.scan(vault, token, str(proj))


def test_supply_flags_unpinned_python(vault, supply_scope):
    proj, token = supply_scope
    (proj / "requirements.txt").write_text("requests>=2.0\nclick==8.1.7\n")
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.python.unpinned" in rids


def test_supply_flags_python_typosquat(vault, supply_scope):
    proj, token = supply_scope
    (proj / "requirements.txt").write_text("reuqests==2.31.0\n")
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.python.typosquat_candidate" in rids


def test_supply_flags_known_malicious_npm(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "dependencies": {"rxnt-authentication": "1.0.0"},
    }))
    findings = supply_chain.scan(vault, token, str(proj))
    rids = {f.rule_id for f in findings}
    assert "argus.supply.npm.known_malicious" in rids


def test_supply_flags_install_scripts(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "scripts": {"postinstall": "node ./build.js"},
    }))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.npm.postinstall_script" in rids


def test_supply_flags_gha_pwn_request(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        on: pull_request_target
        jobs:
          x:
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.pwn_request" in rids


def test_supply_flags_compromised_tj_actions(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  x:\n    steps:\n      - uses: tj-actions/changed-files@v45\n")
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.compromised_action" in rids
