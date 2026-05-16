"""Regression tests for review #8 fix (enrich: max across multiple CVEs)."""

from __future__ import annotations

from argus import intel
from argus.enrich import enrich
from argus.findings import Finding, FindingSet, Severity


class _StubCache:
    def __init__(self, records: dict):
        self._records = records

    def lookup(self, cve_id: str):
        return self._records.get(cve_id)


def _rec(cve_id: str, cvss: float | None, epss: float | None, kev: bool = False):
    return intel.CveRecord(
        cve_id=cve_id, title="", severity="",
        cvss=cvss, epss=epss, kev=kev,
        published="", references=(), raw_source="test",
    )


def test_enrich_takes_max_cvss_across_multiple_cves():
    fs = FindingSet()
    fs.add(Finding(
        rule_id="argus.x.chain", title="chained advisory",
        severity=Severity.HIGH, surface="dynamic", target="example.com",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2099-00001",
            "https://nvd.nist.gov/vuln/detail/CVE-2099-00002",
            "https://nvd.nist.gov/vuln/detail/CVE-2099-00003",
        ),
    ))
    cache = _StubCache({
        "CVE-2099-00001": _rec("CVE-2099-00001", cvss=5.0, epss=0.10),
        "CVE-2099-00002": _rec("CVE-2099-00002", cvss=9.8, epss=0.85),
        "CVE-2099-00003": _rec("CVE-2099-00003", cvss=7.2, epss=0.40),
    })
    out = enrich(fs, cache)
    f = out.findings[0]
    # Must take the worst across the three: CVSS=9.8 (not the first one's 5.0).
    assert f.cvss == 9.8
    assert f.epss == 0.85
    assert f.severity is Severity.CRITICAL  # promoted from HIGH by the 9.8 CVSS


def test_enrich_takes_max_epss_independent_of_cvss():
    """The highest CVSS and highest EPSS can sit on different CVEs."""
    fs = FindingSet()
    fs.add(Finding(
        rule_id="argus.x", title="t", severity=Severity.LOW, surface="dynamic",
        target="example.com",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2099-1001",
            "https://nvd.nist.gov/vuln/detail/CVE-2099-1002",
        ),
    ))
    cache = _StubCache({
        "CVE-2099-1001": _rec("CVE-2099-1001", cvss=8.0, epss=0.10),
        "CVE-2099-1002": _rec("CVE-2099-1002", cvss=4.0, epss=0.95),
    })
    out = enrich(fs, cache)
    f = out.findings[0]
    assert f.cvss == 8.0
    assert f.epss == 0.95


def test_enrich_keeps_existing_cvss_when_higher():
    """If the finding already carries a CVSS higher than the cache entries,
    the existing value must not be lowered."""
    fs = FindingSet()
    fs.add(Finding(
        rule_id="argus.x", title="t", severity=Severity.CRITICAL, surface="dynamic",
        target="example.com", cvss=10.0,
        references=("https://nvd.nist.gov/vuln/detail/CVE-2099-3001",),
    ))
    cache = _StubCache({"CVE-2099-3001": _rec("CVE-2099-3001", cvss=3.0, epss=0.01)})
    out = enrich(fs, cache)
    assert out.findings[0].cvss == 10.0
