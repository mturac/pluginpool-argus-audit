"""Regression tests for review #6 fixes."""

from __future__ import annotations

import textwrap

import pytest

from argus import intel
from argus.errors import IntelError
from argus.scanners import static_python
from argus.scanners import supply_chain


# ---------------------------------------------------------------------------
# 1. _strip_yaml_comments: escapes + block scalars
# ---------------------------------------------------------------------------

def test_strip_yaml_handles_escaped_double_quote():
    """A literal ``#`` inside a double-quoted string with an escaped quote
    earlier in the line must not be stripped."""
    src = 'name: "say \\"hi\\" # not a comment"\n'
    out = supply_chain._strip_yaml_comments(src)
    # Hash inside the string survives.
    assert "# not a comment" in out


def test_strip_yaml_preserves_block_scalar_body():
    src = textwrap.dedent("""
        run: |
          echo hash inside script # NOT a YAML comment
          curl https://x/y # also literal
        # this top-level comment IS removed
        name: ok
    """)
    out = supply_chain._strip_yaml_comments(src)
    assert "echo hash inside script # NOT a YAML comment" in out
    assert "curl https://x/y # also literal" in out
    assert "# this top-level comment IS removed" not in out
    assert "name: ok" in out


def test_strip_yaml_block_scalar_ends_on_dedent():
    src = textwrap.dedent("""
        run: |
          inside
        outside: real # comment
    """)
    out = supply_chain._strip_yaml_comments(src)
    assert "inside" in out
    # The dedented `outside:` line is back in YAML scope; its comment IS stripped.
    assert "outside: real" in out
    assert "outside: real # comment" not in out


# ---------------------------------------------------------------------------
# 2. execute() requires a DB-shaped receiver
# ---------------------------------------------------------------------------

@pytest.fixture()
def static_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


def test_cursor_execute_still_flagged(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "def q(cursor, x):\n    cursor.execute(f'SELECT * FROM t WHERE id={x}')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


def test_unrelated_executor_is_not_a_sql_injection(vault, static_scope):
    """A TaskExecutor.execute() with an f-string is not a SQL injection.
    Pre-fix this was a false positive (MiMo review #6)."""
    proj, token = static_scope
    (proj / "a.py").write_text(
        "class TaskExecutor:\n"
        "    def execute(self, cmd): pass\n"
        "def go(executor, name):\n"
        "    executor.execute(f'run {name}')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" not in rids


def test_self_db_execute_is_flagged(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "class Repo:\n"
        "    def __init__(self, db): self.db = db\n"
        "    def find(self, x):\n"
        "        self.db.execute(f'SELECT {x}')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.sql_string_concat" in rids


# ---------------------------------------------------------------------------
# 3. EPSS date: calendar validation rejects 2026-02-31 (passes regex)
# ---------------------------------------------------------------------------

def test_epss_rejects_impossible_calendar_date(argus_home):
    cache = intel.IntelCache()
    # Regex allows day 31, calendar does not for February.
    with pytest.raises(IntelError):
        intel.fetch_and_apply_epss(cache, date="2026-02-31")
    cache.close()


def test_epss_rejects_month_13(argus_home):
    cache = intel.IntelCache()
    with pytest.raises(IntelError):
        intel.fetch_and_apply_epss(cache, date="2026-13-01")
    cache.close()


def test_epss_accepts_valid_calendar_date(argus_home, monkeypatch):
    cache = intel.IntelCache()
    import gzip
    payload = gzip.compress(b"cve,epss,percentile\nCVE-2099-1,0.1,0.5\n")
    monkeypatch.setattr(intel, "_http_get", lambda url, **kw: payload)
    # 2024 was a leap year, Feb 29 is valid.
    n = intel.fetch_and_apply_epss(cache, date="2024-02-29")
    assert n == 1
    cache.close()
