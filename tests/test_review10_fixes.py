"""Regression tests for review #10 fixes."""

from __future__ import annotations

import json
import textwrap
import time

import pytest

from argus import intel
from argus.findings import Finding, FindingSet, Severity
from argus.scanners import static_python
from argus.scanners import supply_chain


# ---------------------------------------------------------------------------
# 1. SQL injection: keyword-arg + format() bypasses
# ---------------------------------------------------------------------------

@pytest.fixture()
def static_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


def test_sql_via_keyword_arg_is_caught(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "def go(cursor, x):\n"
        "    cursor.execute(query=f'SELECT * FROM t WHERE id={x}')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


def test_sql_via_format_is_caught(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "def go(cursor, x):\n"
        "    cursor.execute('SELECT * FROM t WHERE id={}'.format(x))\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


def test_sql_via_format_on_query_is_caught(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "def go(session, x):\n"
        "    session.query('SELECT {}'.format(x))\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


# ---------------------------------------------------------------------------
# 2. hashlib.new with non-literal algorithm
# ---------------------------------------------------------------------------

def test_hashlib_new_dynamic_is_flagged(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import hashlib\ndef h(alg, data):\n    return hashlib.new(alg, data)\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.weak_hash_dynamic" in rids


# ---------------------------------------------------------------------------
# 3. Finding.rank — KEV now beats EPSS as the tie-breaker
# ---------------------------------------------------------------------------

def test_rank_prefers_kev_over_higher_epss():
    kev_finding = Finding(
        rule_id="argus.x.kev", title="known-exploited",
        severity=Severity.HIGH, surface="dynamic", target="x",
        epss=0.20, kev=True,
    )
    non_kev = Finding(
        rule_id="argus.x.high_epss", title="not exploited",
        severity=Severity.HIGH, surface="dynamic", target="x",
        epss=0.90, kev=False,
    )
    fs = FindingSet()
    fs.add(non_kev)
    fs.add(kev_finding)
    ordered = fs.sorted()
    assert ordered[0].rule_id == "argus.x.kev"


# ---------------------------------------------------------------------------
# 4. npm unpinned: stricter "must be exact semver"
# ---------------------------------------------------------------------------

@pytest.fixture()
def supply_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["supply_chain"])
    return proj, token


def test_npm_x_pattern_is_unpinned(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "dependencies": {"react": "1.2.x"},
    }))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.npm.unpinned" in rids


def test_npm_open_range_is_unpinned(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "dependencies": {"react": "<1.5.0"},
    }))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.npm.unpinned" in rids


def test_npm_hyphen_range_is_unpinned(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "dependencies": {"react": "1.0.0 - 2.0.0"},
    }))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.npm.unpinned" in rids


def test_npm_pinned_with_prerelease_is_ok(vault, supply_scope):
    proj, token = supply_scope
    (proj / "package.json").write_text(json.dumps({
        "name": "x", "version": "0.1.0",
        "dependencies": {"react": "18.2.0-rc.1"},
    }))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.npm.unpinned" not in rids


# ---------------------------------------------------------------------------
# 5. GHA script injection: only flag when interpolation is inside a run: body
# ---------------------------------------------------------------------------

def test_event_in_if_condition_is_not_flagged(vault, supply_scope):
    """A safe `if: ${{ github.event.* }}` guard must NOT raise the
    script-injection alarm (review #10)."""
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        jobs:
          x:
            steps:
              - name: gate
                if: ${{ github.event.pull_request.draft == false }}
                run: echo safe
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.script_injection" not in rids


def test_event_in_run_block_is_flagged(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        jobs:
          x:
            steps:
              - run: |
                  echo "title=${{ github.event.pull_request.title }}"
                  echo done
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.script_injection" in rids


def test_event_in_single_line_run_is_flagged(vault, supply_scope):
    proj, token = supply_scope
    wf = proj / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(textwrap.dedent("""
        jobs:
          x:
            steps:
              - run: echo "${{ github.event.pull_request.title }}"
    """))
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.gha.script_injection" in rids


# ---------------------------------------------------------------------------
# 6. intel.prune_older_than: VACUUM is now conditional
# ---------------------------------------------------------------------------

def test_prune_skips_vacuum_for_small_prune(argus_home):
    """A small prune (<20% of rows) skips VACUUM by default."""
    cache = intel.IntelCache()
    now = int(time.time())
    cache._conn.executemany(
        "INSERT INTO cve (cve_id,title,severity,cvss,epss,kev,published,refs_json,raw_source,fetched_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        [(f"CVE-2099-{i:05d}", "", "", None, None, 0, "", "[]", "test",
          now - (400 if i == 0 else 1) * 86400)  # only the first row is old
         for i in range(20)],
    )
    cache._conn.commit()
    removed = cache.prune_older_than(180)
    assert removed == 1
    cache.close()


def test_prune_vacuum_when_forced(argus_home):
    cache = intel.IntelCache()
    cache._conn.execute(
        "INSERT INTO cve (cve_id,title,severity,cvss,epss,kev,published,refs_json,raw_source,fetched_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("CVE-old", "", "", None, None, 0, "", "[]", "t", int(time.time()) - 1_000 * 86400),
    )
    cache._conn.commit()
    removed = cache.prune_older_than(180, vacuum=True)
    assert removed == 1
    cache.close()
