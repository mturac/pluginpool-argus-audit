"""Regression tests for MiMo-review-driven fixes.

Covers:
    - Static AST detects sinks reached via ``from X import Y``
      (previously bypassable critical finding).
    - intel.fetch_and_apply_nvd_window pages through totalResults.
    - intel.fetch_and_apply_epss inserts rows for previously-unseen CVEs.
    - intel.IntelCache.upsert_cves preserves higher-fidelity NVD CVSS when
      a later KEV ingest carries a blank value.
    - cli._issue_token prints a clean error on a bad proof (no traceback).
    - cli._rotate_key refuses without --confirm.
    - enrich populates cvss/epss/kev from intel cache and promotes severity.
"""

from __future__ import annotations

import gzip
import json

import pytest

from argus import intel
from argus.authz import Vault
from argus.cli import main
from argus.enrich import enrich
from argus.findings import Finding, FindingSet, Severity
from argus.scanners import static_python


# ---------------------------------------------------------------------------
# 1. AST: from-import sink detection (was a critical bypass)
# ---------------------------------------------------------------------------

@pytest.fixture()
def static_scope(vault, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    token = vault.issue("local_path", str(proj), ["static:read"])
    return proj, token


def test_from_import_os_system_is_caught(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("from os import system\nsystem('ls /tmp')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.os_system" in rids


def test_from_import_pickle_loads_is_caught(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("from pickle import loads\nloads(b'data')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.pickle_loads" in rids


def test_aliased_import_is_caught(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text("from pickle import loads as boom\nboom(b'x')\n")
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.pickle_loads" in rids


def test_module_alias_subprocess_shell_true_is_caught(vault, static_scope):
    proj, token = static_scope
    (proj / "a.py").write_text(
        "import subprocess as sp\nsp.run('ls', shell=True)\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.subprocess_shell_true" in rids


def test_unrelated_short_name_is_not_a_false_positive(vault, static_scope):
    """A locally-defined ``system`` must not trip the os.system rule."""
    proj, token = static_scope
    (proj / "a.py").write_text(
        "def system(x):\n    return x\nsystem('ok')\n"
    )
    rids = {f.rule_id for f in static_python.scan(vault, token, str(proj))}
    assert "argus.static.python.os_system" not in rids


# ---------------------------------------------------------------------------
# 2. NVD pagination — follow totalResults across pages
# ---------------------------------------------------------------------------

def _fake_nvd_page(start: int, page_size: int, total: int) -> bytes:
    end = min(start + page_size, total)
    vulnerabilities = []
    for i in range(start, end):
        vulnerabilities.append({
            "cve": {
                "id": f"CVE-2099-{i:05d}",
                "published": "2099-01-01T00:00:00Z",
                "descriptions": [{"lang": "en", "value": f"synthetic #{i}"}],
                "metrics": {},
                "references": [],
            }
        })
    return json.dumps({
        "resultsPerPage": end - start,
        "startIndex": start,
        "totalResults": total,
        "vulnerabilities": vulnerabilities,
    }).encode("utf-8")


def test_nvd_pagination_pulls_every_page(argus_home):
    total = 4321
    page_size = intel.NVD_PAGE_SIZE
    page_calls: list[int] = []

    def fake_fetcher(url: str, headers: dict) -> bytes:
        idx = int(url.split("startIndex=", 1)[1].split("&", 1)[0])
        page_calls.append(idx)
        return _fake_nvd_page(idx, page_size, total)

    cache = intel.IntelCache()
    n = intel.fetch_and_apply_nvd_window(cache, _fetcher=fake_fetcher)
    assert page_calls == [0, page_size, page_size * 2]
    assert n == total
    assert cache.count() == total
    cache.close()


def test_nvd_pagination_single_page_stops(argus_home):
    page_size = intel.NVD_PAGE_SIZE
    payload = _fake_nvd_page(0, page_size, 10)
    calls = {"n": 0}

    def fake_fetcher(url: str, headers: dict) -> bytes:
        calls["n"] += 1
        return payload

    cache = intel.IntelCache()
    n = intel.fetch_and_apply_nvd_window(cache, _fetcher=fake_fetcher)
    assert calls["n"] == 1
    assert n == 10
    cache.close()


# ---------------------------------------------------------------------------
# 3. EPSS inserts unknown CVE rows
# ---------------------------------------------------------------------------

def test_epss_insert_creates_row_for_unknown_cve(argus_home, monkeypatch):
    cache = intel.IntelCache()
    assert cache.count() == 0
    csv = "cve,epss,percentile\nCVE-2099-99999,0.42,0.50\n"
    payload = gzip.compress(csv.encode("utf-8"))
    monkeypatch.setattr(intel, "_http_get", lambda url, **kw: payload)
    intel.fetch_and_apply_epss(cache, date="2099-01-01")
    rec = cache.lookup("CVE-2099-99999")
    assert rec is not None
    assert rec.epss == 0.42
    cache.close()


def test_epss_update_preserves_kev_flag(argus_home, monkeypatch):
    cache = intel.IntelCache()
    kev_payload = json.dumps({
        "vulnerabilities": [{
            "cveID": "CVE-2099-12345", "vulnerabilityName": "Test",
            "knownRansomwareCampaignUse": "Known", "dateAdded": "2099-01-01",
        }]
    }).encode("utf-8")
    cache.upsert_cves(intel.parse_kev(kev_payload))
    csv = "cve,epss,percentile\nCVE-2099-12345,0.88,0.97\n"
    payload = gzip.compress(csv.encode("utf-8"))
    monkeypatch.setattr(intel, "_http_get", lambda url, **kw: payload)
    intel.fetch_and_apply_epss(cache, date="2099-01-01")
    rec = cache.lookup("CVE-2099-12345")
    assert rec is not None
    assert rec.epss == 0.88
    assert rec.kev is True
    cache.close()


# ---------------------------------------------------------------------------
# 4. Severity overwrite: NVD CVSS must survive a later KEV ingest
# ---------------------------------------------------------------------------

def test_kev_ingest_does_not_clobber_nvd_cvss(argus_home):
    cache = intel.IntelCache()
    nvd_payload = json.dumps({
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2099-77777",
                "published": "2099-01-01T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "NVD entry"}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                         "baseSeverity": "CRITICAL"}
                    ]
                },
                "references": [],
            }
        }]
    }).encode("utf-8")
    cache.upsert_cves(intel.parse_nvd_2_0(nvd_payload))
    kev_payload = json.dumps({
        "vulnerabilities": [{"cveID": "CVE-2099-77777",
                              "knownRansomwareCampaignUse": "Unknown",
                              "dateAdded": "2099-01-01"}]
    }).encode("utf-8")
    cache.upsert_cves(intel.parse_kev(kev_payload))
    rec = cache.lookup("CVE-2099-77777")
    assert rec is not None
    assert rec.cvss == 9.8
    assert rec.severity == "CRITICAL"
    assert rec.kev is True
    cache.close()


# ---------------------------------------------------------------------------
# 5. CLI: clean error messages, no tracebacks
# ---------------------------------------------------------------------------

def test_cli_issue_token_prints_friendly_error_on_bad_proof(argus_home, tmp_path, capsys):
    proj = tmp_path / "proj"
    proj.mkdir()
    main(["authorize", "local_path", str(proj)])
    challenge = json.loads(capsys.readouterr().out)
    (proj / ".argus-authz").mkdir()
    (proj / ".argus-authz" / f"{challenge['challenge_id']}.txt").write_text("nope")
    challenge_file = tmp_path / "chal.json"
    challenge_file.write_text(json.dumps(challenge))
    rc = main(["issue-token", "--challenge-file", str(challenge_file),
               "--scopes", "static:read"])
    captured = capsys.readouterr()
    assert rc == 2
    assert "ownership verification failed" in captured.err
    assert "Traceback" not in captured.err


def test_cli_issue_token_handles_missing_file(argus_home, capsys):
    rc = main(["issue-token", "--challenge-file", "/no/such/file", "--scopes", "static:read"])
    captured = capsys.readouterr()
    assert rc == 2
    assert "cannot read challenge file" in captured.err


def test_cli_rotate_key_refuses_without_confirm(argus_home, capsys):
    rc = main(["rotate-key"])
    captured = capsys.readouterr()
    assert rc == 2
    assert "--confirm" in captured.err


def test_cli_rotate_key_with_confirm_rotates(argus_home, capsys):
    vault = Vault()
    token = vault.issue("local_path", str(argus_home), ["static:read"])
    rc = main(["rotate-key", "--confirm"])
    assert rc == 0
    fresh = Vault()
    from argus.errors import AuthzError
    with pytest.raises(AuthzError):
        fresh.parse(token)


# ---------------------------------------------------------------------------
# 6. Enrich: intel cache populates cvss/epss/kev and promotes severity
# ---------------------------------------------------------------------------

class _StubCache:
    def __init__(self, records: dict):
        self._records = records

    def lookup(self, cve_id: str):
        return self._records.get(cve_id)


def test_enrich_populates_cvss_epss_kev():
    fs = FindingSet()
    fs.add(Finding(
        rule_id="argus.http.react2shell_fingerprint",
        title="React2Shell fingerprint",
        severity=Severity.HIGH, surface="dynamic", target="example.com",
        references=("https://nvd.nist.gov/vuln/detail/CVE-2025-55182",),
    ))
    cache = _StubCache({
        "CVE-2025-55182": intel.CveRecord(
            cve_id="CVE-2025-55182", title="React2Shell", severity="CRITICAL",
            cvss=10.0, epss=0.92, kev=True,
            published="2025-12-01", references=(), raw_source="NVD",
        )
    })
    out = enrich(fs, cache)
    assert len(out.findings) == 1
    f = out.findings[0]
    assert f.cvss == 10.0
    assert f.epss == 0.92
    assert f.kev is True
    assert f.severity is Severity.CRITICAL


def test_enrich_does_not_demote_severity():
    fs = FindingSet()
    fs.add(Finding(
        rule_id="argus.static.python.pickle_loads",
        title="pickle.loads()",
        severity=Severity.CRITICAL, surface="static", target="/x",
        references=("https://nvd.nist.gov/vuln/detail/CVE-2020-99999",),
    ))
    cache = _StubCache({
        "CVE-2020-99999": intel.CveRecord(
            cve_id="CVE-2020-99999", title="", severity="LOW",
            cvss=2.0, epss=None, kev=False,
            published="", references=(), raw_source="NVD",
        )
    })
    out = enrich(fs, cache)
    assert out.findings[0].severity is Severity.CRITICAL


def test_enrich_passes_through_findings_without_cves():
    fs = FindingSet()
    fs.add(Finding(
        rule_id="argus.static.python.eval", title="eval",
        severity=Severity.HIGH, surface="static", target="/x",
    ))
    out = enrich(fs, _StubCache({}))
    assert out.findings[0].severity is Severity.HIGH
    assert out.findings[0].cvss is None
