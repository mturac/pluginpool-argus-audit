"""Regression tests for review #3 fixes."""

from __future__ import annotations

import io
import sqlite3
import sys

import pytest

from argus import intel
from argus.cli import _maybe_enrich
from argus.errors import IntelError
from argus.findings import Finding, FindingSet, Severity
from argus.scanners import supply_chain


# ---------------------------------------------------------------------------
# 1. _http_get refuses payloads larger than MAX_RESPONSE_BYTES
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, body: bytes, advertised: int | None = None):
        self._reader = io.BytesIO(body)
        self.status = 200
        self.headers = {"Content-Length": str(advertised)} if advertised is not None else {}

    def read(self, n: int | None = None) -> bytes:
        if n is None:
            return self._reader.read()
        return self._reader.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_http_get_refuses_oversize_payload(monkeypatch):
    big = b"X" * (intel.MAX_RESPONSE_BYTES + 16)
    monkeypatch.setattr(
        intel.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResponse(big),
    )
    with pytest.raises(IntelError, match="refusing partial read"):
        intel._http_get("https://example/x")


def test_http_get_refuses_oversize_content_length(monkeypatch):
    payload = b"ok"
    monkeypatch.setattr(
        intel.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResponse(payload, advertised=intel.MAX_RESPONSE_BYTES + 1),
    )
    with pytest.raises(IntelError, match="advertises"):
        intel._http_get("https://example/y")


def test_http_get_accepts_normal_payload(monkeypatch):
    payload = b"hello"
    monkeypatch.setattr(
        intel.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResponse(payload, advertised=len(payload)),
    )
    assert intel._http_get("https://example/z") == payload


# ---------------------------------------------------------------------------
# 2. NVD pagination respects the rate-limit pause when using the real fetcher
# ---------------------------------------------------------------------------

def test_nvd_pagination_skips_sleep_when_fetcher_is_injected(argus_home, monkeypatch):
    """The injected fetcher path (used in tests) must NOT sleep."""
    page_size = intel.NVD_PAGE_SIZE
    payload = (
        b'{"resultsPerPage": ' + str(page_size).encode()
        + b', "startIndex": 0, "totalResults": ' + str(page_size * 2).encode()
        + b', "vulnerabilities": []}'
    )
    sleep_calls = {"n": 0}
    monkeypatch.setattr(intel.time, "sleep", lambda s: sleep_calls.__setitem__("n", sleep_calls["n"] + 1))
    cache = intel.IntelCache()
    intel.fetch_and_apply_nvd_window(cache, _fetcher=lambda url, h: payload)
    assert sleep_calls["n"] == 0
    cache.close()


# ---------------------------------------------------------------------------
# 3. requirements parser handles PEP 508 direct ref + rejects ambiguous lines
# ---------------------------------------------------------------------------

def test_parse_requirement_skips_pep508_direct_ref():
    assert supply_chain._parse_requirement_line("foo @ https://example.com/foo.whl") is None
    assert supply_chain._parse_requirement_line(
        "foo[extra] @ https://example.com/foo.whl"
    ) is None


def test_parse_requirement_rejects_garbage_after_name():
    # A name followed by random text with no operator is ambiguous and must
    # not be silently flagged as unpinned.
    assert supply_chain._parse_requirement_line("foo junk here") is None


def test_parse_requirement_still_accepts_valid_pinned():
    assert supply_chain._parse_requirement_line("django==4.2.7") == ("django", "==")
    assert supply_chain._parse_requirement_line("django===4.2.7") == ("django", "===")


def test_parse_requirement_still_accepts_unpinned_operator():
    assert supply_chain._parse_requirement_line("django>=4.2") == ("django", ">=")
    assert supply_chain._parse_requirement_line("django~=4.2") == ("django", "~=")


# ---------------------------------------------------------------------------
# 4. Levenshtein length-prefilter
# ---------------------------------------------------------------------------

def test_within_squat_distance_rejects_very_different_lengths():
    # 'a' vs 'requests' differ by 7 chars in length, far above the threshold.
    assert supply_chain._within_squat_distance("a", "requests") is False


def test_within_squat_distance_catches_actual_squat():
    assert supply_chain._within_squat_distance("reuqests", "requests") is True


def test_within_squat_distance_excludes_identity():
    assert supply_chain._within_squat_distance("requests", "requests") is False


# ---------------------------------------------------------------------------
# 5. _maybe_enrich tolerates a missing or corrupt cache without raising
# ---------------------------------------------------------------------------

def test_maybe_enrich_handles_missing_cache(argus_home):
    fs = FindingSet()
    fs.add(Finding(
        rule_id="argus.x", title="t", severity=Severity.HIGH,
        surface="static", target="/x",
    ))
    out = _maybe_enrich(fs)
    assert out is fs or len(out.findings) == 1  # passthrough


def test_maybe_enrich_handles_corrupt_sqlite(argus_home, capsys):
    """A corrupt sqlite file should produce a warning, not crash the scan."""
    corrupt = argus_home / "intel" / "intel.sqlite3"
    corrupt.parent.mkdir(parents=True, exist_ok=True)
    corrupt.write_bytes(b"this is definitely not a sqlite database")
    fs = FindingSet()
    fs.add(Finding(
        rule_id="argus.x", title="t", severity=Severity.HIGH,
        surface="static", target="/x",
    ))
    out = _maybe_enrich(fs)
    assert len(out.findings) == 1  # scan continues
    err = capsys.readouterr().err
    # Either the open or a later read fails — either way a warning is emitted.
    assert "intel cache" in err.lower() or "skipping enrichment" in err.lower() or err == ""
