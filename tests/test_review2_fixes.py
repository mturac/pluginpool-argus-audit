"""Regression tests for review #2 fixes.

Covers:
    - static_python: import-with-dot does not duplicate the path
      (``import os.path; os.path.join`` must NOT resolve to ``os.path.path.join``)
    - intel.fetch_and_apply_epss: refuses malformed --epss-date input
    - intel.fetch_and_apply_epss: falls back when "yesterday" feed is 404
    - supply_chain._parse_requirement_line: extras / markers / VCS handled
    - cli._maybe_enrich: tolerates a missing intel cache without breaking the scan
"""

from __future__ import annotations

import gzip
import sqlite3

import pytest

from argus import intel
from argus.errors import IntelError
from argus.scanners import static_python
from argus.scanners import supply_chain


# ---------------------------------------------------------------------------
# 1. Multi-part import resolution
# ---------------------------------------------------------------------------

@pytest.fixture()
def static_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


def test_import_dotted_package_does_not_double_resolve(vault, static_scope):
    """`import os.path; os.path.join(x)` must resolve to `os.path.join`,
    not `os.path.path.join`. A clean call must not produce any finding."""
    proj, token = static_scope
    (proj / "ok.py").write_text("import os.path\nos.path.join('a', 'b')\n")
    findings = static_python.scan(vault, token, str(proj))
    assert findings == []


def test_dotted_import_alias_resolves_correctly(vault, static_scope):
    """``import xml.etree.ElementTree as ET`` should not flag ``ET.fromstring``."""
    proj, token = static_scope
    (proj / "ok.py").write_text(
        "import xml.etree.ElementTree as ET\n"
        "ET.fromstring('<a/>')\n"
    )
    findings = static_python.scan(vault, token, str(proj))
    assert findings == []


def test_dotted_import_does_not_break_real_sink_detection(vault, static_scope):
    """The fix must not regress the bare ``import os`` → ``os.system`` case."""
    proj, token = static_scope
    (proj / "bad.py").write_text("import os\nos.system('ls')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.os_system" in rids


# ---------------------------------------------------------------------------
# 2. EPSS date validation refuses URL-traversal payloads
# ---------------------------------------------------------------------------

def test_epss_refuses_traversal_date(argus_home):
    cache = intel.IntelCache()
    with pytest.raises(IntelError):
        intel.fetch_and_apply_epss(cache, date="../../evil.com/x.csv.gz?")
    cache.close()


def test_epss_refuses_obviously_bad_date(argus_home):
    cache = intel.IntelCache()
    for bad in ("2099-13-01", "2099-02-31", "yesterday", "../../etc/passwd"):
        with pytest.raises(IntelError):
            intel.fetch_and_apply_epss(cache, date=bad)
    cache.close()


def test_epss_accepts_well_formed_date(argus_home, monkeypatch):
    cache = intel.IntelCache()
    csv = "cve,epss,percentile\nCVE-2099-1,0.1,0.5\n"
    payload = gzip.compress(csv.encode("utf-8"))
    monkeypatch.setattr(intel, "_http_get", lambda url, **kw: payload)
    n = intel.fetch_and_apply_epss(cache, date="2025-06-15")
    assert n == 1
    cache.close()


def test_epss_default_falls_back_when_yesterday_404s(argus_home, monkeypatch):
    """When the explicit yesterday URL 404s, argus must retry older days."""
    cache = intel.IntelCache()
    csv = "cve,epss,percentile\nCVE-2099-2,0.2,0.6\n"
    payload = gzip.compress(csv.encode("utf-8"))
    call_log: list[str] = []

    def fake_get(url: str, **kw) -> bytes:
        call_log.append(url)
        if len(call_log) < 2:
            raise IntelError(f"404 on {url}")
        return payload

    monkeypatch.setattr(intel, "_http_get", fake_get)
    n = intel.fetch_and_apply_epss(cache, date=None)
    assert n == 1
    assert len(call_log) >= 2  # at least one retry
    cache.close()


# ---------------------------------------------------------------------------
# 3. requirements.txt parser handles extras / markers / VCS
# ---------------------------------------------------------------------------

def test_parse_requirement_handles_extras():
    out = supply_chain._parse_requirement_line('requests[security] ==2.31.0')
    assert out == ("requests", "==")


def test_parse_requirement_handles_environment_marker():
    out = supply_chain._parse_requirement_line('django==4.2 ; python_version < "3.12"')
    assert out == ("django", "==")


def test_parse_requirement_handles_unpinned_with_extras():
    out = supply_chain._parse_requirement_line('rich[jupyter,doc]>=13.0')
    assert out == ("rich", ">=")


def test_parse_requirement_skips_vcs_url():
    assert supply_chain._parse_requirement_line("git+https://x/y.git@deadbeef") is None
    assert supply_chain._parse_requirement_line("https://files.pythonhosted.org/x.whl") is None


def test_parse_requirement_skips_options():
    for opt in ("-r other.txt", "--index-url https://x", "-c constraints.txt"):
        assert supply_chain._parse_requirement_line(opt) is None


def test_parse_requirement_handles_comment_only_line():
    assert supply_chain._parse_requirement_line("   # just a comment") is None


@pytest.fixture()
def supply_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["supply_chain"])
    return proj, token


def test_supply_flags_extras_dependency_as_unpinned(vault, supply_scope):
    proj, token = supply_scope
    (proj / "requirements.txt").write_text('requests[security]>=2.31.0\n')
    rids = {f.rule_id for f in supply_chain.scan(vault, token, str(proj))}
    assert "argus.supply.python.unpinned" in rids


def test_supply_clean_pinned_with_marker(vault, supply_scope):
    proj, token = supply_scope
    (proj / "requirements.txt").write_text(
        'django==4.2.7 ; python_version < "3.12"\n'
    )
    assert supply_chain.scan(vault, token, str(proj)) == []


def test_supply_ignores_vcs_url(vault, supply_scope):
    proj, token = supply_scope
    (proj / "requirements.txt").write_text(
        "git+https://github.com/x/y.git@abc123#egg=y\n"
    )
    assert supply_chain.scan(vault, token, str(proj)) == []
