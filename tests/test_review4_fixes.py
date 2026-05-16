"""Regression tests for review #4 fixes."""

from __future__ import annotations

import textwrap

import pytest

from argus.cli import _maybe_enrich
from argus.findings import Finding, FindingSet, Severity
from argus.scanners import supply_chain


# ---------------------------------------------------------------------------
# 1. _maybe_enrich must not crash when IntelCache construction raises
# ---------------------------------------------------------------------------

def test_maybe_enrich_survives_intelcache_construction_error(argus_home, monkeypatch, capsys):
    """If IntelCache() raises during construction, the finally block must
    still be safe (cache stays bound to None)."""

    class _Bomb(Exception):
        pass

    def explode():
        raise OSError("cannot open intel cache")

    from argus import intel
    monkeypatch.setattr(intel, "IntelCache", explode)
    fs = FindingSet()
    fs.add(Finding(rule_id="argus.x", title="t", severity=Severity.HIGH,
                   surface="static", target="/x"))
    out = _maybe_enrich(fs)
    assert len(out.findings) == 1
    err = capsys.readouterr().err
    assert "intel cache unavailable" in err
    # And — most importantly — no UnboundLocalError leaked out.


# ---------------------------------------------------------------------------
# 2. GHA permission scopes
# ---------------------------------------------------------------------------

@pytest.fixture()
def supply_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["supply_chain"])
    return proj, token


def test_supply_flags_contents_write_permission(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        permissions:
          contents: write
        jobs:
          x:
            steps:
              - run: echo hi
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.permission_write_contents" in rids


def test_supply_flags_id_token_write(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        permissions:
          id-token: write
        jobs:
          x:
            steps:
              - run: echo hi
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.permission_write_id_token" in rids


def test_supply_flags_write_all_as_high(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        permissions: write-all
        jobs:
          x:
            steps:
              - run: echo hi
    """))
    findings = supply_chain.scan(vault, token, str(proj))
    rids = {f.rule_id for f in findings}
    assert "argus.supply.gha.permission_write_all" in rids
    high_or_critical = [f for f in findings if f.severity.name in {"HIGH", "CRITICAL"}]
    assert any(f.rule_id == "argus.supply.gha.permission_write_all" for f in high_or_critical)


def test_supply_does_not_flag_read_permission(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        permissions:
          contents: read
        jobs:
          x:
            steps:
              - run: echo hi
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert not any(r.startswith("argus.supply.gha.permission_write") for r in rids)
