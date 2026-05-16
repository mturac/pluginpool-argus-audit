"""Regression tests for review #7 fixes."""

from __future__ import annotations

import textwrap
import time

import pytest

from argus import intel
from argus.cli import main
from argus.scanners import static_python
from argus.scanners import supply_chain


# ---------------------------------------------------------------------------
# 1. SQL receiver names — env-var extension
# ---------------------------------------------------------------------------

@pytest.fixture()
def static_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


def test_extra_sql_receiver_via_env(vault, static_scope, monkeypatch):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "def go(results, x):\n    results.execute(f'SELECT {x}')\n"
    )
    # Without env var, `results.execute(...)` is treated as non-SQL.
    monkeypatch.delenv("ARGUS_SQL_RECEIVERS", raising=False)
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" not in rids

    # With env var, `results` joins the allowlist.
    monkeypatch.setenv("ARGUS_SQL_RECEIVERS", "results, other_thing")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


def test_extra_sql_receivers_built_in_query(vault, static_scope, monkeypatch):
    proj, token = static_scope
    monkeypatch.delenv("ARGUS_SQL_RECEIVERS", raising=False)
    (proj / "a.py").write_text(
        "def go(query, x):\n    query.execute(f'SELECT {x}')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    # `query` is now in the built-in list (review #7).
    assert "argus.static.python.sql_string_concat" in rids


# ---------------------------------------------------------------------------
# 2. YAML block-header detection ignores `|` inside quoted scalars
# ---------------------------------------------------------------------------

def test_strip_yaml_ignores_pipe_inside_quoted_scalar():
    src = textwrap.dedent("""
        description: "Check for: |"
        # this comment must STILL be stripped because no real block scalar opened
        contents: write
    """)
    out = supply_chain._strip_yaml_comments(src)
    assert "# this comment must STILL be stripped" not in out
    assert "contents: write" in out


def test_real_block_scalar_after_quoted_pipe_still_detected():
    src = textwrap.dedent("""
        description: "Check for: |"
        run: |
          echo body
        # outside block, must be stripped
        name: x
    """)
    out = supply_chain._strip_yaml_comments(src)
    assert "echo body" in out
    assert "# outside block, must be stripped" not in out


# ---------------------------------------------------------------------------
# 3. NVD page delay scales with NVD_API_KEY presence
# ---------------------------------------------------------------------------

def test_nvd_page_delay_anon_is_slow(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    assert intel._nvd_page_delay() == intel.NVD_PAGE_DELAY_ANON_S


def test_nvd_page_delay_drops_with_api_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "fakekey")
    assert intel._nvd_page_delay() == intel.NVD_PAGE_DELAY_AUTHED_S


# ---------------------------------------------------------------------------
# 4. subprocess shell= non-literal → MEDIUM warning, shell=False → silent
# ---------------------------------------------------------------------------

def test_subprocess_shell_dynamic_is_flagged_as_medium(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import subprocess\n"
        "def go(opts):\n"
        "    subprocess.run(['ls'], shell=opts.use_shell)\n"
    )
    findings = static_python.scan(vault, token, str(proj))
    rids = {f.rule_id for f in findings}
    assert "argus.static.python.subprocess_shell_dynamic" in rids
    dyn = [f for f in findings if f.rule_id == "argus.static.python.subprocess_shell_dynamic"]
    assert dyn[0].severity.name == "MEDIUM"


def test_subprocess_shell_false_is_silent(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import subprocess\nsubprocess.run(['ls'], shell=False)\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.subprocess_shell_true" not in rids
    assert "argus.static.python.subprocess_shell_dynamic" not in rids


# ---------------------------------------------------------------------------
# 5. intel cache prune_older_than removes old rows + CLI command works
# ---------------------------------------------------------------------------

def test_prune_older_than_drops_old_rows(argus_home):
    cache = intel.IntelCache()
    cache._conn.execute(
        "INSERT INTO cve (cve_id, title, severity, cvss, epss, kev, published, "
        "refs_json, raw_source, fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("CVE-old", "old", "HIGH", None, None, 0, "", "[]", "test",
         int(time.time()) - 365 * 86400),
    )
    cache._conn.execute(
        "INSERT INTO cve (cve_id, title, severity, cvss, epss, kev, published, "
        "refs_json, raw_source, fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("CVE-new", "new", "HIGH", None, None, 0, "", "[]", "test", int(time.time())),
    )
    cache._conn.commit()
    assert cache.count() == 2
    removed = cache.prune_older_than(180)  # half a year
    assert removed == 1
    assert cache.count() == 1
    assert cache.lookup("CVE-new") is not None
    assert cache.lookup("CVE-old") is None
    cache.close()


def test_cli_intel_prune_reports_count(argus_home, capsys):
    cache = intel.IntelCache()
    cache._conn.execute(
        "INSERT INTO cve (cve_id, title, severity, cvss, epss, kev, published, "
        "refs_json, raw_source, fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("CVE-old", "old", "HIGH", None, None, 0, "", "[]", "test",
         int(time.time()) - 365 * 86400),
    )
    cache._conn.commit()
    cache.close()
    rc = main(["intel-prune", "--max-age-days", "180"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "pruned 1" in out


def test_prune_older_than_refuses_negative(argus_home):
    cache = intel.IntelCache()
    with pytest.raises(ValueError):
        cache.prune_older_than(-1)
    cache.close()
